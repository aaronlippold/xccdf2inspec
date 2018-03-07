# xccdf2inspec
The XCCDF to InSpec parser scans and extracts the controls defined in the DISA XCCDF 
STIG XML documents and converts them into InSpec control 'stubs' to help ease the 
pain of InSpec profile developers everywhere.

# Usage
## Command Line
```
#>bundle exec ruby xccdf2inspec exec help
Usage: xccdf2inspec.rb [options]
    -x, --xccdf xccdf                the path to the disa stig xccdf file
    -c, --cci cci                    the path to the cci xml file
    -g, --group group1,group2,group3 A CSV list of the group you want to process
	in the XCCDF file
    -o, --output output.rb           The name of the inspec file you want
    -f, --format [ruby|hash]         The format you would like (defualt: ruby)
    -s, --seperate [true|false]      If you want to break the controls into seperate files (defualt: false)
    -v, --version                    xccdf2inspec version
    -h, --help                       Displays Help
```
## Documentation
The script is documented in YARD. (http://yardoc.org) If you should ever want documentation.

## Known Issues
- Issues welcome - please submit suggestions or issues on the board.
