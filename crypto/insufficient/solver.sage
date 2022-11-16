from Crypto.Util.number import long_to_bytes

cipher = 115139400156559163067983730101733651044517302092738415230761576068368627143021367186957088381449359016008152481518188727055259259438853550911696408473202582626669824350180493062986420292176306828782792330214492239993109523633165689080824380627230327245751549253757852668981573771168683865251547238022125676591
p = 8200291410122039687250292442109878676753589397818032770561720051299309477271228768886216860911120846659270343793701939593802424969673253182414886645533851
shares = [((6086926015098867242735222866983726204461220951103360009696454681019399690511733951569533187634005519163004817081362909518890288475814570715924211956186561, 180544606207615749673679003486920396349643373592065733048594170223181990080540522443341611038923128944258091068067227964575144365802736335177084131200721), 358596622670209028757821020375422468786000283337112662091012759053764980353656144756495576189654506534688021724133853284750462313294554223173599545023200), ((1386358358863317578119640490115732907593775890728347365516358215967843845703994105707232051642221482563536659365469364255206757315665759154598917141827974, 4056544903690651970564657683645824587566358589111269611317182863269566520886711060942678307985575546879523617067909465838713131842847785502375410189119098), 7987498083862441578197078091675653094495875014017487290616050579537158854070043336559221536943501617079375762641137734054184462590583526782938983347248670), ((656537687734778409273502324331707970697362050871244803755641285452940994603617400730910858122669191686993796208644537023001462145198921682454359699163851, 7168506530157948082373212337047037955782714850395068869680326068416218527056283262697351993204957096383236610668826321537260018440150283660410281255549702), 1047085825033120721880384312942308021912742666478829834943737959325181775143075576517355925753610902886229818331095595005460339857743811544053574078662507), ((5258797924027715460925283932681628978641108698338452367217155856384763787158334845391544834908979711067046042420593321638221507208614929195171831766268954, 4425317882205634741873988391516678208287005927456949928854593454650522868601946818897817646576217811686765487183061848994765729348913592238613989095356071), 866086803634294445156445022661535120113351818468169243952864826652249446764789342099913962106165135623940932785868082548653702309009757035399759882130676)]


w_0 = 2**128
w_1 = 2**256

mat = matrix(ZZ, 11, 11)
for i in range(4):
    mat[i, i] = p
    mat[4, i] = -shares[i][0][0]
    mat[5, i] = -pow(shares[i][0][0], 2)
    mat[6, i] = -pow(shares[i][0][0], 3)
    mat[7, i] = -shares[i][0][1]
    mat[8, i] = -pow(shares[i][0][1], 2)
    mat[9, i] = -pow(shares[i][0][1], 3)
    mat[10, i] = int(shares[i][1])

for i in range(6):
    mat[4+i, 4+i] = w_0

mat[10, 10] = w_1

M = mat.LLL()    

# find a1, a2, a3, b1, b2 and b3
coeffs = []
for i in range(4, 10):
	assert int(M[0][i]) % w_0 == 0
	coeffs.append(int(int(M[0][i]) // w_0))

assert int(M[0][10]) == w_1

m_1 = int(M[0][0])
m_2 = int(M[0][1])
m_3 = int(M[0][2])
m_4 = int(M[0][3])

c = GCD(m_1 - m_2, m_1 - m_3)
assert int(c).bit_length() == 128

s = int(m_1 % c)
assert int(s + c).bit_length() > 128

coeffs.append(c)
coeffs.append(s)

key = 0
for coeff in coeffs:
    key <<= 128
    key ^^= coeff

print(long_to_bytes(key ^^ cipher))
# SECCON{Unfortunately_I_could_not_come_up_with_a_more_difficult_problem_than_last_year_sorry...-6fc18307d3ed2e7673a249abc2e0e22c}
