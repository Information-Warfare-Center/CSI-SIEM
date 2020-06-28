# This script generates the bin-list.bro script.
# It uses data from: http://elliottback.com/wp/bank-identification-number-bin-list/

require 'csv'
require 'set'

puts "module CreditCardExposure;"
puts
puts "export {"
puts "	type Bank: record {"
puts "		typ:      string;"
puts "		name:     string;"
puts "	} &log;"
puts
puts "	const bin_list: table[count] of Bank = {"
i = 0
bins=Set.new
CSV.foreach("bin-list.csv") do |row|
	i+=1
	next if i == 1
	next if row[0] !~ /^[0-9]+$/
	bin = row[0]
	next if bins.include?(bin)
	bins << bin
	location = row[1].to_s.gsub(/\"/, "\\\"")
	type = row[2].to_s.gsub(/\"/, "\\\"")
	name = row[3].to_s.gsub(/\"/, "\\\"")
	puts "		[#{bin}] = [$typ=\"#{type}\", $name=\"#{name}\"],"
end

puts "	} &redef;"
puts "}"
