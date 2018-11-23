# MERGED into `inspec_tools` gem
## NOTE: This repo is **no longer maintained** here. Please use [inspec_tools](https://github.com/mitre/inspec_tools).

# xccdf2inspec
The XCCDF to InSpec parser scans and extracts the controls defined in the DISA XCCDF 
STIG XML documents and converts them into InSpec control 'stubs' to help ease the 
pain of InSpec profile developers everywhere.

## Versioning and State of Development
This project uses the [Semantic Versioning Policy](https://semver.org/). 

### Branches
The master branch contains the latest version of the software leading up to a new release. 

Other branches contain feature-specific updates. 

### Tags
Tags indicate official releases of the project.

Please note 0.x releases are works in progress (WIP) and may change at any time.   

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

## NOTICE

© 2018 The MITRE Corporation.  

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.  

## NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  
