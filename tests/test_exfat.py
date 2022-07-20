from dissect.fat import exfat


def test_exfat(exfat_simple):
    e = exfat.ExFAT(exfat_simple)

    assert e.volume_label == "THESIS"
    assert e.cluster_count == 1792
    assert e.sector_size == e.cluster_size
    assert e.fat_sector == 128
    assert e.root_dir_cluster == 15
    assert e.root_dir_sector == 269
    assert e.runlist(e.root_dir_cluster) == [(e.root_dir_sector, 1)]

    files = e.files
    assert sorted(files.keys()) == ["/"]

    root = files["/"][0]
    assert root.metadata.attributes.directory == 1
    assert root.stream.flags.not_fragmented == 0
    assert root.stream.data_length == 512

    cat = files["/"][1]["cat.jpg"][0]
    assert cat.metadata.attributes.directory == 0
    assert cat.stream.flags.not_fragmented == 1
    assert cat.stream.data_length == 88786

    find_me = files["/"][1]["find_me.txt"][0]
    assert find_me.metadata.attributes.directory == 0
    assert find_me.stream.flags.not_fragmented == 1
    assert find_me.stream.data_length == 9

    directory = files["/"][1]["directory"][0]
    assert directory.metadata.attributes.directory == 1
    assert directory.stream.flags.not_fragmented == 1
    assert directory.stream.data_length == 512

    sysvol = files["/"][1]["System Volume Information"][0]
    assert sysvol.metadata.attributes.directory == 1
    assert sysvol.stream.flags.not_fragmented == 1
    assert sysvol.stream.data_length == 512
