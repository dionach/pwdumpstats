# pwdumpstats
pwdumpstats is a python script to generate statistics from a pwdump file, including around the use of duplicate passwords. It can also read passwords cracked using John the Ripper or hashcat, to show the most common weak passwords in use.

Although it will work with any pwdump file (or even a simpler username:hash file), it is best used with the output of [NtdsAudit](https://github.com/Dionach/ntdsaudit), which will allow it to output more stats, such as those related to inactive and administrative accounts.

Comments and pull requests are welcome.

## Usage

pwdumpstats will try and find John's pot file (which contains the cracked passwords) by looking in the `$JOHN` environment variable. If this isn't set, you can manually pass the pot file to it with `--pot`. It also supports pot files in from hashcat, and potentially other tools as long as they use the same formatting.

```
usage: pwdumpstats.py [options] <pwdumpfile>

optional arguments:
  -h, --help                            Show help text
  -f FILTER_FILE, --filter FILTER_FILE  Filter users
  -H, --history                         Include password history hashes
  -s, --show                            Show full password re-use output
  -a, --admins                          List admins
  -A, --cracked-admins                  List cracked admin accounts
  -n, --noncomplex                      List users with non-complex passwords
  -E, --empty                           List users with empty passwords
  -c, --cracked                         Only print cracked hashes
  -d, --domain                          Print domains
  -D, --disabled                        Include disabled accounts
  -p POT_FILE, --pot POT_FILE           Specify pot file (john or hashcat format)
  -m, --mask                            Mask passwords and hashes in output
  -l, --lm                              Show accounts with LM hashes
```


## Example Output
```
$ pwdumpstats.py pwdump.txt

##############
# Statistics #
##############

Users:                  7359
LM Hashes (current):    360 (4.89%)
LM Hashes (history):    0
History hashes:         0
Total hashes:           7359

Cracked passwords:      5857 (79.59%)
Non-complex passwords:  494 (6.71%)
Empty passwords:        0

Duplicate passwords:    1509 (20.51%)
Highest duplicate:      167 (2.27%)
Top 20 passwords:       747 (10.15%)

Username as password:   23 (0.31%)

Total admin accounts:   99
Cracked admin passwords 68 (68.69%)
Administrators:         99
Domain Admins:          61

Top 20 hashes

310     64F12CDDAA88057E06A81B54E73B949B        Password1
131     30C3F921B4A69289FE7E752E0E3BAEAB        Monday10
49      31D6CFE0D16AE931B73C59D7E0C089C0        [empty]
38      DA7A992199887B5652528077CDD049CC        October2017
35      A4258E2B5D7D7FBB04531A89177B5E22        November2017
<...>
```
