import doctest, cymruwhois

def test_doctest():
    fail, ok = doctest.testmod(cymruwhois)
    assert fail == 0
