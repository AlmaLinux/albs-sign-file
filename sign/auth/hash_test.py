from .hash import hash_valid, get_hash


def test_good():
    """
    Testing with good password
    Exect that check will pass
    """
    test_pass = "veryverrystrong"
    test_hash = get_hash(test_pass)
    assert hash_valid(test_pass, test_hash)
