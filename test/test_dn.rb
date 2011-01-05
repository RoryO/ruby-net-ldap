require 'common'
require 'net/ldap/dn'

class TestDN < Test::Unit::TestCase
  DN = Net::LDAP::DN

  def test_to_s
    assert_equal("cn=Jam\\<m\\>y,ou=Com\\,pany", DN.new("cn","Jam<m>y","ou=Com\\,pany").to_s)
  end

  def test_to_ber
    # Tests the proxying, as we do not define our own to_ber method in DN
    assert_equal("\004\031cn=Jam\\<m\\>y,ou=Com\\,pany", DN.new("cn","Jam<m>y","ou=Com\\,pany").to_ber)
  end

  def test_to_a
    # Uses each internally, so also tests each
    assert_equal(["cn","Jam<m>y","ou","Com,pany"], DN.new("cn=Jam\\<m\\>y,ou=Com\\,pany").to_a)
  end

  def test_entry
    entry = Net::LDAP::Entry.new(Net::LDAP::DN.new("cn","Jam<m>y","ou=Com\\,pany"))
    assert_equal("dn: cn=Jam\\<m\\>y,ou=Com\\,pany\n", entry.to_ldif)
  end
end
