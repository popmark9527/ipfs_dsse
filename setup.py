import Function
B = 8000
def setup(pdb, key):
    dict_l_d = {}
    dict_A = {}
    for pdb_keyword in pdb.keys():
        key_1 = Function.EnCrypt(key, "1" + pdb_keyword)
        key_2 = Function.EnCrypt(key, "2" + pdb_keyword)
        if len(pdb[pdb_keyword]) < B:
            while len(pdb[pdb_keyword]) % B != 0:
                pdb[pdb_keyword] += ' '
            keyword_id_filehash = Function.filehash(pdb[pdb_keyword])
            dict_l = Function.f(key_1, 0)
            dict_d = Function.EnCrypt(key_2, keyword_id_filehash)
            dict_l_d[dict_l] = dict_d
        if len(pdb[pdb_keyword]) >= B:
            T = pdb[pdb_keyword] / B
            i = 0
            dict_I = {}
            if i < T:
                dict_I["I_" + str(i)] = pdb[pdb_keyword][8000 * i + 1: 8000 + i * 8000]
                i = i + 1
            while len(pdb[pdb_keyword][1 + 8000 * (T - 1):]) % B != 0:
                pdb[pdb_keyword] += ' '
            dict_I["I+" + str(T)] = pdb[pdb_keyword][8000 * (T - 1) + 1: 8000 + T * 8000]
            dict_filehash_I = {}
            ind = Function.randomStr(15)
            dict_A[ind] = []
            for i in dict_I:
                dict_filehash_I["I_filehash" + str(i)] = Function.filehash(dict_I["I_" + str(i)])
                dict_A[ind].append(Function.EnCrypt(key_2, dict_filehash_I["I_filehash" + str(i)]))
            dict_l = Function.f(key_1, 0)
            dict_d = Function.EnCrypt(key_2, dict_A[ind])
            dict_l_d[dict_l] = dict_d
        return [dict_l_d, dict_A]

