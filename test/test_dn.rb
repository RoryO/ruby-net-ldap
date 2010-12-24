require 'common'

class TestDN < Test::Unit::TestCase
  DN = Net::LDAP::DN

  def test_to_s
    assert_equal("cn=Jam\\<m\\>y,ou=Com\\,pany", DN.new("cn","Jam<m>y","ou=Com\\,pany").to_s)
  end

  def test_to_a
    # Uses each internally, so also tests each
    assert_equal(["cn","Jam<m>y","ou","Com,pany"], DN.new("cn=Jam\\<m\\>y,ou=Com\\,pany").to_a)
  end
end
