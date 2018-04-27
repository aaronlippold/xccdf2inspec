# xccdf2inspec
The XCCDF to InSpec parser scans and extracts the controls defined in the DISA XCCDF 
STIG XML documents and converts them into InSpec control 'stubs' to help ease the 
pain of InSpec profile developers everywhere.

# Usage

## Install needed gems

`bundle install`

## Command Line
```
#>bundle exec ruby xccdf2inspec exec help

XCCDF2Inspec translates an xccdf file to an inspec profile

	-x --xccdf : Path to the disa stig xccdf file
	-c --cci : Path to the cci xml file
	-o --output : The name of the inspec file you want
	-f --format [ruby | hash] : The format you would like (defualt: ruby)
	-s --seperate-files [true | false] : Output the resulting controls as one or mutlple files (defualt: true)

example: ./xccdf2inspec exec -c cci_list.xml -x xccdf_file.xml -o myprofile -f ruby
```
## Documentation
The script is documented in YARD. (http://yardoc.org) If you should ever want documentation.

## Known Issues
- Issues welcome - please submit suggestions or issues on the board.
