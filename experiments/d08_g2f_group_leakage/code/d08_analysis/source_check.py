import sys, json, pandas as pd, numpy as np
IN=sys.argv[1]; KEY=["package","old_version","new_version"]
tr=pd.read_csv(IN+'/d08_train.csv',dtype=str,keep_default_na=False); te=pd.read_csv(IN+'/d08_test.csv',dtype=str,keep_default_na=False)
d7=pd.read_csv(IN+'/d07b_baselines.csv',dtype=str,keep_default_na=False)
gr=pd.read_csv(IN+'/d08_groups.csv',dtype=str,keep_default_na=False)
meta=pd.DataFrame(json.load(open(IN+'/d08_mal_meta.json')))
meta=meta[meta.split=='main']
meta['src_type']=meta.malicious_source.map(lambda d:d.get('type')); meta['src_ver']=meta.malicious_source.map(lambda d:d.get('verification'))
ALL=pd.concat([tr.assign(split='train'),te.assign(split='test')])
M=ALL[ALL.label=='1'].merge(gr[KEY+['campaign','changedJsSetSha1','largestChangedJsSha1']],on=KEY).merge(meta[KEY+['src_type','src_ver','label_verification','collection_round']],on=KEY,how='left')
old_keys=set(map(tuple,d7[(d7['class']=='malicious')&(d7.split=='main')][KEY].values))
M['era']=np.where(M[KEY].apply(tuple,axis=1).isin(old_keys),'pre_D08(Linux)','new_D08(Windows)')
F=[c for c in tr.columns if c not in KEY+['label']]
for c in F:
    if c!='updateType': M[c]=pd.to_numeric(M[c].replace({'True':'1','False':'0','':np.nan}))
print(pd.crosstab([M.split,M.era],M.src_type))
print(pd.crosstab(M.era,M.src_ver))
# identical changed-JS set across eras -> ChangedCode features should be identical
cc=[c for c in F if c.endswith('ChangedCode')]+['obfChangedFileCount']
x=M[M.changedJsSetSha1!='']
both=x.groupby('changedJsSetSha1').era.nunique(); hs=both[both>1].index
print('changedJsSet hashes present in both eras:',len(hs),'rows',int(x.changedJsSetSha1.isin(hs).sum()))
diff=0; tot=0; ex=[]
for h in hs:
    g=x[x.changedJsSetSha1==h]
    for c in cc:
        vals=g.groupby('era')[c].apply(lambda s: tuple(sorted(set(s.round(12).dropna()))))
        tot+=1
        if len(set(vals.values))>1: diff+=1; ex.append((h[:10],c,dict(vals)))
print('feature x hash comparisons',tot,'differ',diff); [print(' ',e) for e in ex[:12]]
# within same hash & same era, are ChangedCode features constant?
w=0; wt=0
for (h,e),g in x.groupby(['changedJsSetSha1','era']):
    if len(g)<2: continue
    for c in cc:
        wt+=1; w+= g[c].round(12).nunique(dropna=False)>1
print('within (hash,era) groups: comparisons',wt,'non-constant',w)
# source type vs features within campaigns that have >1 source
for camp,g in M[M.split=='train'].groupby('campaign'):
    if g.src_type.nunique()>1 and len(g)>=20:
        t=g.groupby('src_type').agg(n=('package','size'),isa=('installScriptAdded','mean'),interval_med_days=('updateInterval',lambda s:s.median()/86400),hexNew=('obfHexIdentRatioNew','median'),ws=('obfWhitespaceRatioChangedCode','median'),patch=('updateType',lambda s:(s=='patch').mean()))
        print('==',camp); print(t.round(3).to_string())
