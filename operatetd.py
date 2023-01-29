import Function
def operate_search_td(key, keyword):
    key_1 = Function.EnCrypt(key, "1" + keyword)
    key_2 = Function.EnCrypt(key, "2" + keyword)
    key_3 = Function.EnCrypt(key, "3" + keyword)
    key_4 = Function.EnCrypt(key, "4" + keyword)

def operate_update_td(key, keyword):
    key_3 = Function.EnCrypt(key, "3" + keyword)
    key_4 = Function.EnCrypt(key, "4" + keyword)