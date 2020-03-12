# pwcheck
Simple crypt()-based /etc/shadow password hash linter (in D)

## usage
```
$ ./pwcheck
```

## build
```
$ dub -brelease
```

## configuration
Build it with a suitable list of weak passwords in includes/weak\_passwords.list

There's no further configuration: the idea is to drop a binary on a Unix server and run it.

## ideal output
(nothing)

## useful output
```
alice has a weak password of: abc123
```
