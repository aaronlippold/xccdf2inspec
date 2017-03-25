# xccdf2inspec
WIP: The XCCDF to InSpec parser scans and extracts the controls defined in the DISA XCCDF STIG XML documents and converts them into InSpec control 'stubs' to help ease the pain of inspec profile developers everywhere.

# Usage
## Command Line
```
#>ruby xccdf2inspec.rb --help
Usage: xccdf2inspec.rb [options]
    -x, --xccdf xccdf                the path to the disa stig xccdf file
    -c, --cci cci                    the path to the cci xml file
    -g, --group group1,group2,group3 A CSV list of the group you want to process
	in the XCCDF file
    -o, --output output.rb           The name of the inspec file you want
    -f, --format [ruby|hash]         The format you would like (defualt: ruby)
    -v, --version                    xccdf2inspec version
    -h, --help                       Displays Help
```
## Options

## Assumptions

## Known Issues
- Issues welcome :)
