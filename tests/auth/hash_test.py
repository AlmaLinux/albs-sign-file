from sign.auth.hash import hash_valid, get_hash


def test_good():
    """
    Testing with good password
    Expect that check will pass
    """
    test_pass = "veryverrystrong"
    test_hash = get_hash(test_pass)
    assert hash_valid(test_pass, test_hash)

def test_bad():
    """
    Testing with bad password 
    Expecting that check will fail
    """
    test_pass = "veryverrystrong"
    test_hash = get_hash(test_pass)
    assert not hash_valid("bad_pass", test_hash)