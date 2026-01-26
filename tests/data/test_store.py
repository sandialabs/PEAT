from peat import Datastore, DeviceData


def test_datastore_create():
    store = Datastore()
    dev = store.create("192.168.0.1", "ip")
    assert isinstance(dev, DeviceData)
    assert len(store.objects) == 1
    assert store.objects[0] is dev
    assert store.objects[0].ip == "192.168.0.1"


def test_datastore_get():
    store = Datastore()
    dev = store.get("192.168.1.2")
    assert dev.ip == "192.168.1.2"
    assert len(store.objects) == 1
    dm = DeviceData()
    dm.ip = "10.0.0.2"
    store.objects.append(dm)
    assert store.get("10.0.0.2") is dm


def test_datastore_search():
    store = Datastore()
    dm = DeviceData(mac="00:11:22:33:44:55")
    store.objects.append(dm)
    assert store.search("00:11:22:33:44:55", "mac") is dm
    assert not store.search("192.168.1.1", "ip")


def test_datastore_remove():
    store = Datastore()
    dm = DeviceData(mac="00:11:22:33:44:55")
    store.objects.append(dm)
    assert store.objects[0] is dm
    assert store.remove(dm)
    assert not store.objects
    assert not store.remove(dm)


def test_datastore_prune_inactive():
    store = Datastore()
    assert store.prune_inactive() is None
    dm = DeviceData(mac="00:11:22:33:44:55")
    dm._is_active = True
    store.objects.append(dm)
    d2 = DeviceData(ip="1.1.1.1")
    d2._is_active = False
    store.objects.append(d2)
    store.prune_inactive()
    assert d2 not in store.objects
    assert store.objects[0] is dm


def test_datastore_deduplicate():
    store = Datastore()
    assert store.deduplicate() is None
    dupe_ip = "192.0.2.3"
    d1 = store.get(dupe_ip)
    d1._is_verified = True
    d1._is_active = True
    d2 = store.get("192.0.2.2")
    d2._is_active = True
    d3 = store.get("172.16.3.3")
    d4 = DeviceData(ip=dupe_ip)
    store.objects.append(d4)
    assert len(store.objects) == 4
    store.deduplicate(prune_inactive=False)
    assert len(store.objects) == 3
    assert d3 in store.objects
    store.deduplicate(prune_inactive=True)
    assert len(store.objects) == 2
    assert d3 not in store.objects


def test_datastore_properties():
    store = Datastore()
    d1 = store.get("192.0.2.3")
    d1._is_verified = True
    d1._is_active = True
    d2 = store.get("192.0.2.2")
    d2._is_active = True
    d3 = store.get("172.16.3.3")
    assert store.verified == [d1]
    assert store.objects == [d1, d2, d3]
