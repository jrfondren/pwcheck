import std.string : splitLines, toStringz, fromStringz;
import std.typecons : Tuple;
import sumtype;

extern(C) char* crypt(const(char)* key, const(char)* salt);

immutable string[] weaks = import("weak_passwords.list").splitLines;
immutable(char)*[] weakz;
shared static this() {
	import std.algorithm : map;
	import std.array : array;
	weakz = weaks.map!toStringz.array;
}

struct NotWeak {}
struct NoPassword {}
struct DESPassword {}
struct WeakDESPassword { string pass; }
struct WeakPassword { string pass; }
alias Weakness = SumType!(NotWeak, NoPassword, DESPassword,
	WeakPassword, WeakDESPassword);

Weakness isWeak(string hash) @trusted {
	import std.regex : regex, matchFirst;
	import core.stdc.string: strcmp;
	import std.range : iota;

	// man 5 shadow
	if (hash == "*") return NotWeak().Weakness;
	if (hash == "") return NoPassword().Weakness;
	if (hash[0] == '!') return NotWeak().Weakness;
	
	// man 3 crypt
	enum hashre = regex(`(^[$](?:1|2a|5|6)[$][^$]+[$])`);
	const m = hash.matchFirst(hashre);
	if (m) {
		const salt = m[1].toStringz;
		const hashz = hash.toStringz;
		foreach (i; iota(weaks.length))
			if (0 == strcmp(hashz, crypt(weakz[i], salt)))
				return WeakPassword(weaks[i]).Weakness;
		return NotWeak().Weakness;
	} else {
		const salt = hash[0 .. 2].toStringz;
		const hashz = hash.toStringz;
		foreach (i; iota(weaks.length))
			if (0 == strcmp(hashz, crypt(weakz[i], salt)))
				return WeakDESPassword(weaks[i]).Weakness;
		return DESPassword().Weakness;
	}
}

@safe unittest {
	assert(isWeak("$1$YzTLPnhJ$OZoHkjAYlIgCmOKQi.PXn.").match!(w => w.pass == "password", _ => false));
	assert(isWeak("$1$YzTLPnhJ$mvaycoMIyVr/NaEHKzB5H0").match!((NotWeak _) => true, _ => false));
	assert(isWeak("!foo").match!((NotWeak _) => true, _ => false));
	assert(isWeak("*").match!((NotWeak _) => true, _ => false));
	assert(isWeak("").match!((NoPassword _) => true, _ => false));
	assert(isWeak("foo").match!((DESPassword _) => true, _ => false));
	assert(isWeak("lhBnWgIh1qed6").match!((WeakDESPassword w) => w.pass == "monkey", _ => false));
}

void lint(string user, string hash) @safe {
	import std.stdio : writeln;

	isWeak(hash).match!(
		(WeakPassword w) => writeln(user, " has weak password of: ", w.pass),
		(WeakDESPassword w) => writeln(user, " has weak (DES!) password of: ", w.pass),
		(NotWeak _) {},
		(NoPassword _) => writeln(user, " lacks a password! This is dangerous!"),
		(DESPassword _) => writeln(user, " has an old DES-style password hash! This is dangerous!")
	);
}

alias UserPass = Tuple!(string, "user", string, "pass");
UserPass[] hashes() @trusted {
	import std.regex : regex, matchFirst;
	import std.stdio : File;
	import std.algorithm : map;
	import std.array : array;

	enum hashre = regex(`^([^:]+):([^:]+):`);
	return File("/etc/shadow")
		.byLineCopy
		.map!((string line) {
			auto m = line.matchFirst(hashre);
			return UserPass(m[1], m[2]);
		}).array;
}

void main() @safe {
	foreach (up; hashes()) {
		lint(up.user, up.pass);
	}
}
