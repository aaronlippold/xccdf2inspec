# xccdf2inspec
The XCCDF to InSpec parser scans and extracts the controls defined in the DISA XCCDF 
STIG XML documents and converts them into InSpec control 'stubs' to help ease the 
pain of InSpec profile developers everywhere. Now added support for IA Controls as well, 
it will provide you with the NIST tags.

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
	-m --mapping-xls XLS file that maps between IA Controls and 800-53 NIST tags (ex: ./mapper.xls)
	-v --verbose : Prints out each IA Control (default: false)


example: example:./xccdf2inspec exec -c cci.xml -x xccdf.xml -o myprofile2 -m ./mapper.xls -v true
```
## Documentation
The script is documented in YARD. (http://yardoc.org) If you should ever want documentation.

## Known Issues
- Issues welcome - please submit suggestions or issues on the board.
