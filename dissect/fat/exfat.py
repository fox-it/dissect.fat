import os
import logging
import struct
from itertools import groupby
from operator import itemgetter
from collections import OrderedDict

from dissect.util.stream import RangeStream, RunlistStream

from dissect.fat.c_exfat import (
    c_exfat,
    BITMAP_ENTRY,
    DIR_ENTRY_SIZE,
    EOC,
    FAT_ENTRY_SIZE,
    FILE_ENTRY,
    NO_VOLUME_LABEL_ENTRY,
    UPCASE_TABLE_ENTRY,
    VOLUME_LABEL_ENTRY,
)
from dissect.fat.exceptions import InvalidHeaderMagic

__all__ = ["ExFAT"]

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_EXFAT", "CRITICAL"))


class ExFAT:
    def __init__(self, fh):
        self.filesystem = fh
        fh.seek(0)

        self.vbr = c_exfat.EXFAT_HEADER(fh.read(512))
        self.fs_name = self.vbr.fs_name
        if self.fs_name != b"EXFAT   ":
            raise InvalidHeaderMagic("Invalid exFAT header magic")

        # These get stored as exponents
        self.sector_size = 2**self.vbr.bytes_per_sector_exp
        self.cluster_size = self.sector_size * (2**self.vbr.sectors_per_cluster_exp)

        self.fat_sector = self.vbr.fat_sector  # Almost always sector 128 (absolute)
        self.fat_sector_count = self.vbr.fat_sector_count
        self.fat_size = self.fat_sector_count * self.sector_size
        self.fat = RangeStream(fh, (self.fat_sector * self.sector_size), self.fat_size)

        self.cluster_heap_sector = self.vbr.cluster_heap_sector
        self.cluster_count = self.vbr.cluster_heap_count
        self.root_dir_cluster = self.vbr.root_dir_cluster
        self.root_dir_sector = self.cluster_to_sector(self.root_dir_cluster)
        self.root_directory = RootDirectory(fh, self.root_dir_cluster, self)
        self.files = self.root_directory.dict  # maybe linked list to be able to traverse sub directories easier?

        self.alloc_bitmap = self.root_directory.bitmap_entry
        self.upcase_table = self.root_directory.upcase_entry
        self.volume_label = self.root_directory.volume_entry.volume_label.strip("\x00")

    def cluster_to_sector(self, cluster):
        """
        Returns the clusters' corresponding sector address

        Args:
            cluster (int): cluster address

        Returns:
            int: corresponding sector address if available
        """

        sector = ((cluster - 2) * (2**self.vbr.sectors_per_cluster_exp)) + self.cluster_heap_sector
        return sector if sector > 0 else None

    def sector_to_cluster(self, sector):
        """
        Returns the sectors' corresponding cluster address

        Args:
            sector (int): sector address

        Returns:
            int: corresponding cluster address if available
        """

        cluster = ((sector - self.cluster_to_sector(2)) // self.sector_size) + 2
        return cluster if cluster >= 2 else None

    def runlist(self, starting_cluster, not_fragmented=True, size=None):
        """
        Creates a RunlistStream compatible runlist from exFAT FAT structures

        Args:
            starting_cluster (int): First cluster of file, folder or location in question

        Returns:
            runlist: [(sector_offset, run_length)]"""

        # If file is not fragmented clusters will not be present in the FAT
        cluster_chain = [starting_cluster] if not_fragmented else self.get_cluster_chain(starting_cluster)
        runlist = []

        # TODO Graceful way to construct a runlist of non-fragmented streams spanning multiple sectors
        if size:
            run = -(-size // self.cluster_size)
            runlist.append((self.cluster_to_sector(cluster_chain[0]), run))
        else:
            # This is a somewhat convoluted, but short way to group successive
            # clusters together.
            # As the cluster numbers in the cluster_chain are strictly
            # incrementing, a succesive range of clusters will have the same
            # delta with respect to their position in the cluster_chain, which
            # is different from any other successive range, which is what is
            # used in the groupby().
            for _, cluster_group in groupby(enumerate(cluster_chain), lambda i: i[0] - i[1]):
                run = list(map(itemgetter(1), cluster_group))
                start_cluster = run[0]
                run_len = len(run)
                runlist.append((self.cluster_to_sector(start_cluster), run_len))

        return runlist

    def get_cluster_chain(self, starting_cluster):
        """
        Reads the on disk FAT to construct the cluster chain

        Args:
            starting_cluster (int): cluster to look-up the chain from

        Returns:
            list: Chain of clusters. Including starting_cluster
        """

        next_ = 0x00000000
        chain = []

        if starting_cluster < 2:
            return chain
        else:
            while next_ != EOC:
                self.fat.seek(starting_cluster * FAT_ENTRY_SIZE)
                next_ = struct.unpack("<L", self.fat.read(FAT_ENTRY_SIZE))[0]
                chain.append(starting_cluster)
                starting_cluster = next_

            return chain

    @staticmethod
    def _utc_timezone(timezone):
        """
        Converts a Microsoft exFAT timezone byte to its UTC timezone equivalent

        Args:
            timezone (int): exFAT timezone byte

        Returns:
            dict: UTC name (str), UTC offset in minutes (int)
        """

        #    utc_bool -64 32 16 : 8 4 2 1
        #              ^ sign
        TIMEZONE_MINUTE_INCREMENT = 15
        utc_enabled = timezone >> 7
        signed = (timezone >> 6) & 0x11  # Check if the second bit is set

        if utc_enabled:
            if signed:
                utc_minute_offset = ((timezone & 0x3F) - 64) * TIMEZONE_MINUTE_INCREMENT
            else:
                utc_minute_offset = (timezone & 0x7F) * TIMEZONE_MINUTE_INCREMENT

            hours, minutes = divmod(utc_minute_offset, 60)
            utc_name = f"UTC{hours:+03}:{minutes:02}"

            return {"name": utc_name, "offset": utc_minute_offset}
        else:
            return {"name": "localtime", "offset": 0}


class RootDirectory:
    def __init__(self, fh, location, exfat):
        self.exfat = exfat
        self.location = location
        self.size = 0
        self.root_dir = None
        self.volume_entry = None
        self.upcase_entry = None
        self.bitmap_entry = None
        self.dict = OrderedDict()
        self._parse_root_dir(fh)

    def _parse_root_dir(self, fh):
        """
        Parses the passed fh to construct the Root directory object"""

        # Root dir is always present in FAT so we pass False to traverse the FAT table
        # thus root dir is per definition fragmented
        runlist = self.exfat.runlist(self.location, False)
        size = 0

        # Calculate size of rootdir from runlist since rootdir has no size attribute
        for run in runlist:
            size += run[1] * self.exfat.cluster_size

        self.size = size
        self.root_dir = RunlistStream(fh, runlist, self.size, self.exfat.cluster_size)
        self.dict = self._create_root_dir(self.root_dir)

    def _parse_subdir(self, entry):
        """
        Parses the given sub directory file directory entry for containing files

        Args:
            entry (FILE): Directory FILE entry

        Returns:
            OrderedDict: Containing files in sub directory
        """

        folder_location = entry.stream.location
        folder_size = entry.stream.data_length
        folder_runlist = self.exfat.runlist(folder_location, not_fragmented=entry.stream.flags.not_fragmented)

        fh = RunlistStream(self.exfat.filesystem, folder_runlist, folder_size, self.exfat.cluster_size)
        return self._parse_file_entries(fh)

    @staticmethod
    def _construct_filename(fn_entries, is_dir=False):
        """
        Assembles the filename from given file name directory entries

        Args:
            fn_entries (list): A list of exFAT file name directory entries

        Returns:
            str: Name of file or folder stripped from trailing null values
        """

        filename = []
        if len(fn_entries) == 1:
            filename = fn_entries[0].filename.strip("\x00")
        else:
            for fn_entry in fn_entries:
                filename.append(fn_entry.filename)

            filename = "".join(filename).strip("\x00")

        return filename if not is_dir else filename + "/"

    def _parse_file_entries(self, fh):
        """
        Finds and parses file entries in a given file handle (file like object)

        Args:
            fh (Stream object): Any stream object

        Returns:
            OrderedDict: Found and parsed file directory entries
        """

        entries = OrderedDict()

        while fh.tell() < fh.size:
            entry = c_exfat.FILE_DIRECTORY_ENTRY(fh.read(DIR_ENTRY_SIZE))

            if entry.entry_type == FILE_ENTRY:  # Or entry.entry_type == 0x05:
                # Entry is a file so we reuse it
                metadata = entry

                # -1 because the metadata entry includes the stream dir entry in its count
                fnentry_count = metadata.subentry_count - 1

                stream = c_exfat.STREAM_DIRECTORY_ENTRY(fh.read(DIR_ENTRY_SIZE))
                fn_entries = []

                for _ in range(fnentry_count):
                    fn_entries.append(c_exfat.FILENAME_DIRECTORY_ENTRY(fh.read(DIR_ENTRY_SIZE)))

                file_ = c_exfat.FILE(metadata=metadata, stream=stream, fn_entries=fn_entries)
                if file_.metadata.attributes.directory:
                    # A directory will have its own file entry as it's first element
                    # and a ordered dict of file entry contained in it which can be accessed by their corresponding keys
                    filename = self._construct_filename(file_.fn_entries)
                    entries[filename] = (file_, self._parse_subdir(file_))
                else:
                    filename = self._construct_filename(file_.fn_entries)
                    entries[filename] = (file_, None)
            else:
                self._non_file_entries(entry)

        return entries

    def _non_file_entries(self, entry):
        if entry.entry_type == VOLUME_LABEL_ENTRY or entry.entry_type == NO_VOLUME_LABEL_ENTRY:
            self.volume_entry = c_exfat.VOLUME_DIRECTORY_ENTRY(entry.dumps())
        elif entry.entry_type == BITMAP_ENTRY:
            self.bitmap_entry = c_exfat.BITMAP_DIRECTORY_ENTRY(entry.dumps())
        elif entry.entry_type == UPCASE_TABLE_ENTRY:
            self.upcase_entry = c_exfat.UPCASE_DIRECTORY_ENTRY(entry.dumps())

    def _create_root_dir(self, root_dir):
        """
        Since exFAT does not have a dedicated root directory entry
        one has to be constructed form available parameters during filesystem parsing.

        This is ballpark so no real forensic conclusions should be based on the information of the root entry
        """

        metadata = c_exfat.FILE_DIRECTORY_ENTRY(
            entry_type=0x85, subentry_count=2, attributes=c_exfat.ATTRIBUTES(directory=0b1)
        )

        stream = c_exfat.STREAM_DIRECTORY_ENTRY(
            entry_type=0xC0,
            flags=c_exfat.FILE_FLAGS(allocation_possible=0b0, not_fragmented=0b0),
            filename_length=1,
            location=self.location,
            data_length=self.size,
        )

        fn_entries = [
            c_exfat.FILENAME_DIRECTORY_ENTRY(
                entry_type=0xC1, flags=0x00, filename="/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
        ]

        root_entry = OrderedDict()
        root_entry["/"] = (
            c_exfat.FILE(metadata=metadata, stream=stream, fn_entries=fn_entries),
            self._parse_file_entries(root_dir),
        )

        return root_entry
