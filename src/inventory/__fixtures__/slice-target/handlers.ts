/** Fixture for the slicer: braces hide in strings, templates, regexes and comments. */

const SQL = "select * from users where meta->>'{a}' = '{b}'";
const TEMPLATE = `prefix ${SQL.length > 0 ? "{" : "}"} suffix`;
const BRACED = /^\{[^}]*\}$/u;

/* a block comment with a stray { brace */

/** Short handler whose whole body fits in any sane budget. */
export function shortHandler(id: string): string {
  const decoded = decodeURIComponent(id); // a trailing } in a comment
  return `${SQL}:${TEMPLATE}:${BRACED.test(decoded)}`;
}

/** Handler whose signature is spread over several lines. */
// biome-ignore format: the slicer has to climb a signature that spans lines.
export async function wideSignature(
  first: string,
  second: number,
): Promise<string> {
  const joined = `${first}-${second}`;
  return joined;
}

/** Long handler used to prove the budget and the elision markers. */
export function longHandler(seed: number): number {
  let total = seed;
  total += 1; // step 1
  total += 2; // step 2
  total += 3; // step 3
  total += 4; // step 4
  total += 5; // step 5
  total += 6; // step 6
  total += 7; // step 7
  total += 8; // step 8
  total += 9; // step 9
  total += 10; // step 10
  total += 11; // step 11
  total += 12; // step 12
  total += 13; // step 13
  total += 14; // step 14
  total += 15; // step 15
  total += 16; // step 16
  total += 17; // step 17
  total += 18; // step 18
  total += 19; // step 19
  total += 20; // step 20
  total += 21; // step 21
  total += 22; // step 22
  total += 23; // step 23
  total += 24; // step 24
  total += 25; // step 25
  total += 26; // step 26
  total += 27; // step 27
  total += 28; // step 28
  total += 29; // step 29
  total += 30; // step 30
  total += 31; // step 31
  total += 32; // step 32
  total += 33; // step 33
  total += 34; // step 34
  total += 35; // step 35
  total += 36; // step 36
  total += 37; // step 37
  total += 38; // step 38
  total += 39; // step 39
  total += 40; // step 40
  total += 41; // step 41
  total += 42; // step 42
  total += 43; // step 43
  total += 44; // step 44
  total += 45; // step 45
  total += 46; // step 46
  total += 47; // step 47
  total += 48; // step 48
  total += 49; // step 49
  total += 50; // step 50
  total += 51; // step 51
  total += 52; // step 52
  total += 53; // step 53
  total += 54; // step 54
  total += 55; // step 55
  total += 56; // step 56
  total += 57; // step 57
  total += 58; // step 58
  total += 59; // step 59
  total += 60; // step 60
  total += 61; // step 61
  total += 62; // step 62
  total += 63; // step 63
  total += 64; // step 64
  total += 65; // step 65
  total += 66; // step 66
  total += 67; // step 67
  total += 68; // step 68
  total += 69; // step 69
  total += 70; // step 70
  total += 71; // step 71
  total += 72; // step 72
  total += 73; // step 73
  total += 74; // step 74
  total += 75; // step 75
  total += 76; // step 76
  total += 77; // step 77
  total += 78; // step 78
  total += 79; // step 79
  total += 80; // step 80
  total += 81; // step 81
  total += 82; // step 82
  total += 83; // step 83
  total += 84; // step 84
  total += 85; // step 85
  total += 86; // step 86
  total += 87; // step 87
  total += 88; // step 88
  total += 89; // step 89
  total += 90; // step 90
  total += 91; // step 91
  total += 92; // step 92
  total += 93; // step 93
  total += 94; // step 94
  total += 95; // step 95
  total += 96; // step 96
  total += 97; // step 97
  total += 98; // step 98
  total += 99; // step 99
  total += 100; // step 100
  total += 101; // step 101
  total += 102; // step 102
  total += 103; // step 103
  total += 104; // step 104
  total += 105; // step 105
  total += 106; // step 106
  total += 107; // step 107
  total += 108; // step 108
  total += 109; // step 109
  total += 110; // step 110
  total += 111; // step 111
  total += 112; // step 112
  total += 113; // step 113
  total += 114; // step 114
  total += 115; // step 115
  total += 116; // step 116
  total += 117; // step 117
  total += 118; // step 118
  total += 119; // step 119
  total += 120; // step 120
  total += 121; // step 121
  total += 122; // step 122
  total += 123; // step 123
  total += 124; // step 124
  total += 125; // step 125
  total += 126; // step 126
  total += 127; // step 127
  total += 128; // step 128
  total += 129; // step 129
  total += 130; // step 130
  total += 131; // step 131
  total += 132; // step 132
  total += 133; // step 133
  total += 134; // step 134
  total += 135; // step 135
  total += 136; // step 136
  total += 137; // step 137
  total += 138; // step 138
  total += 139; // step 139
  total += 140; // step 140
  total += 141; // step 141
  total += 142; // step 142
  total += 143; // step 143
  total += 144; // step 144
  total += 145; // step 145
  total += 146; // step 146
  total += 147; // step 147
  total += 148; // step 148
  total += 149; // step 149
  total += 150; // step 150
  total += 151; // step 151
  total += 152; // step 152
  total += 153; // step 153
  total += 154; // step 154
  total += 155; // step 155
  total += 156; // step 156
  total += 157; // step 157
  total += 158; // step 158
  total += 159; // step 159
  total += 160; // step 160
  return total;
}

/** Registered at the top level, with no enclosing block at all. */
export const registrations = [
  { path: "/a", handler: shortHandler },
  { path: "/b", handler: wideSignature },
];
