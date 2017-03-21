# xccdf2inspec
WIP: The XCCDF to InSpec parser scans and extracts the controls defined in the DISA XCCDF STIG XML documents and converts them into InSpec control 'stubs' to help ease the pain of inspec profile developers everywhere.

# Usage
## Command Line
```
#>ruby xccdf2inspec.rb --help
Usage: xccdf2inspec.rb [options]
    -x, --xccdf xccdf                the path to the disa stig xccdf file
    -c, --cci cci                    the path to the cci xml file
    -g, --group V-72857              The name of the specific group you want to process in the XCCDF file
    -o, --output output.rb           The name of the inspec file you want
    -h, --help                       Displays Help
```
## Options

## Assumptions

## Known Issues
 - Currenly can only sub-process one group item - i.e. stig control, we are working on adding the ability to process a comma seperated list you can pass in.
 - The parser currently has issues with escaping chars in some of the text blocks which is causing issues "downstream" with the controls. We are currently working on this issue.
 - TBD :)
