$0 ~ "*/" {
	p = 0;
}

p && $0 !~ "[ /]* SECTION: " {
	#cl[section] += gensub(/ * \?/, "", "g", $0);
	cl[section] = cl[section]  gensub(/ \* ?/, "", "1", $0) "\n";
}

$0 ~ "[ /]* SECTION: " {
	section = $3;
	sl[len++] = section;
	tl[section] = gensub(/^[\/ ]\* SECTION: [^ ]+ +/, "", "1", $0);
	p = 1;
}

END {
	asort(sl);
	for (i in sl) {
		section = sl[i]
		print(tl[section]);
		a = section
		c = gsub(/\./, "", a);
		if (c == 0)
			r = "=";
		else if (c == 1)
			r = "*"
		else if (c == 2)
			r = "+"
		else
			r = "-"
		print(gensub(/./, r, "g", tl[section]));
		print(cl[section]);
	}
}
