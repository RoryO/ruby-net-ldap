# LDAP DN support classes
#

##
# Objects of this class represent an LDAP DN.
#
# In LDAP-land, a DN ("Distinguished Name") is a unique identifier for an
# entry within an LDAP directory. It is made up of a number of other
# attributes strung together, to identify the entry in the tree.
#
# Each attribute that makes up a DN needs to have its value escaped so that
# the DN is valid. This class helps take care of that.
#
# A fully escaped DN needs to be unescaped when analysing its contents. This
# class also helps take care of that.
class Net::LDAP::DN
  ##
  # Initialize a DN, escaping as required. Pass in attributes in name/value
  # pairs. If there is a left over argument, it will be appended to the dn
  # without escaping (useful for a base string).
  # 
  # Most uses of this class will be to escape a DN, rather than to parse it,
  # so storing the dn as an escaped String and parsing parts as required with
  # a state machine seems sensible.
  def initialize(*args)
    buffer = StringIO.new

    args.each_index do |index|
      buffer << "=" if index % 2 == 1
      buffer << "," if index % 2 == 0 && index != 0

      if index < args.length - 1 || index % 2 == 1
        buffer << Net::LDAP::DN.escape(args[index])
      else
        buffer << args[index]
      end
    end

    @dn = buffer.string
  end

  ##
  # Parse the DN into key/value pairs.
  def each_pair
    state = :key
    key = StringIO.new
    value = StringIO.new
    hex_buffer = ""

    @dn.each_char do |char|
      case state
        when :key then case char
          when '\\' then state = :key_escape
          when '=' then state = :value
          else key << char
        end
        when :value then case char
          when '\\' then state = :value_escape
          when ',' then state = :key; yield key.string, value.string; key = StringIO.new; value = StringIO.new;
          else value << char
        end
        when :key_escape then case char
          when "0".."9","a".."f","A".."F" then state = :key_escape_hex; hex_buffer = char
          else state = :key; key << char
        end
        when :key_escape_hex then case char
          when "0".."9","a".."f","A".."F" then state = :key; key << "#{hex_buffer}#{char}".to_i(16).chr
          else raise "DN badly formed"
        end
        when :value_escape then case char
          when "0".."9","a".."f","A".."F" then state = :value_escape_hex; hex_buffer = char
          else state = :value; value << char
        end
        when :value_escape_hex then case char
          when "0".."9","a".."f","A".."F" then state = :value; value << "#{hex_buffer}#{char}".to_i(16).chr
          else raise "DN badly formed"
        end
      end
    end
    # Last pair
    yield key.string, value.string
  end

  ##
  # Returns the DN as an array in the form expected by the constructor.
  def to_a
    a = []
    self.each_pair { |key, value| a << key << value }
    a
  end

  ##
  # Return the DN as an escaped string.
  def to_s
    @dn
  end

  ##
  # Escape a string for use in an LDAP dn. Escapes required characters by
  # prefixing with a \.
  def self.escape(value)
    value.gsub(/[,=+<>#;\\"]/) {|s| "\\#{s}" } 
  end

  ##
  # Proxy all other requests to the string object, because a DN is mainly
  # used within the library as a string
  def method_missing(method, *args, &block)
    @dn.send(method, *args, &block)
  end
end
