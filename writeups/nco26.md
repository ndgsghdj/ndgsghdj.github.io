---
id: 5
title: "National Cybersecurity Olympiad 2026"
subtitle: "Writeups for the pwn challenges that I solved (which is all of them eventually)"
date: "2026.04.12"
tags: "writeups"
---

Around two weeks ago, I participated in the National Cybersecurity Olympiad (NCO) 2026 qualifications and finals, where for the first time I not only had to do pwn, but also actually manage other categories (horror!).

It was very fun, also considering that I'd managed to solve all the qualification pwn challenges during the timeframe, as well as 2/3 of the finals pwn during the contest.

These are the various writeups for the challenges that I had solved (as well as the one challenge I could not during the contest).

# Quals

i will write these in the order that i solved them

## pwn/delta

### Challenge Protections

{{<component name="terminal">}}
Arch:       amd64-64-little
RELRO:      {{<component name="color" color="yellow">}}Partial RELRO {{</component>}}
Stack:      {{<component name="color" color="red">}}No canary found{{</component>}}
NX:         {{<component name="color" color="green">}}NX enabled{{</component>}}
PIE:        {{<component name="color" color="red">}}No PIE (0x3fe000){{</component>}}
RUNPATH:    {{<component name="color" color="red">}}b'.'{{</component>}}
Stripped:   {{<component name="color" color="red">}}No{{</component>}}
{{</component>}}
