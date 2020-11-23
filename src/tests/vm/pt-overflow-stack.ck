# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(pt-overflow-stack) begin
(pt-overflow-stack) grew stack 1 times
(pt-overflow-stack) grew stack 2 times
(pt-overflow-stack) grew stack 3 times
(pt-overflow-stack) grew stack 4 times
(pt-overflow-stack) grew stack 5 times
(pt-overflow-stack) grew stack 6 times
(pt-overflow-stack) grew stack 7 times
(pt-overflow-stack) grew stack 8 times
(pt-overflow-stack) grew stack 9 times
(pt-overflow-stack) grew stack 10 times
(pt-overflow-stack) grew stack 11 times
(pt-overflow-stack) grew stack 12 times
(pt-overflow-stack) grew stack 13 times
(pt-overflow-stack) grew stack 14 times
(pt-overflow-stack) grew stack 15 times
(pt-overflow-stack) grew stack 16 times
(pt-overflow-stack) grew stack 17 times
(pt-overflow-stack) grew stack 18 times
(pt-overflow-stack) grew stack 19 times
(pt-overflow-stack) grew stack 20 times
(pt-overflow-stack) grew stack 21 times
(pt-overflow-stack) grew stack 22 times
(pt-overflow-stack) grew stack 23 times
(pt-overflow-stack) grew stack 24 times
(pt-overflow-stack) grew stack 25 times
(pt-overflow-stack) grew stack 26 times
(pt-overflow-stack) grew stack 27 times
(pt-overflow-stack) grew stack 28 times
(pt-overflow-stack) grew stack 29 times
(pt-overflow-stack) grew stack 30 times
pt-overflow-stack: exit(-1)
EOF
pass;
