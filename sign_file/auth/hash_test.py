from .hash import check_hash, get_hash


def test_good():
    """
    Testing with good password
    Exect that check will pass
    """
    test_pass = "veryverrystrong"
    test_hash = get_hash(test_pass)
    assert check_hash(test_pass, test_hash)
