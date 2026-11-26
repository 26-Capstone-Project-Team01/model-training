import sys, pandas as pd, numpy as np
IN=sys.argv[1]; KEY=["package","old_version","new_version"]
tr=pd.read_csv(IN+'/d08_train.csv',dtype=str,keep_default_na=False); sa=pd.read_csv(IN+'/d08_split_assignment.csv',dtype=str,keep_default_na=False)
d6=pd.read_csv(IN+'/d06_train.csv',dtype=str,keep_default_na=False)
tr=tr.merge(sa[KEY+['class','splitGroup']],on=KEY)
F=[c for c in tr.columns if c not in KEY+['label','class','splitGroup']]
sets={'no_updateInterval':[f for f in F if f!='updateInterval'],
      'no_updateInterval_no_New':[f for f in F if f!='updateInterval' and not f.endswith('New')],
      'changed_code_only':[f for f in F if f.endswith('ChangedCode')]+['obfChangedFileCount','installScriptAdded','scriptEntryAdded','newDependencyAdded','newDependencyCount']}
for name,cols in sets.items():
    v=tr[cols].agg('|'.join,axis=1)
    print('==',name,len(cols))
    for c in ['malicious','benign','hard_benign']:
        s=v[tr['class']==c]; vc=s.value_counts()
        print(f'  {c}: rows {len(s)} unique {s.nunique()} rows_in_repeated {int(s.duplicated(keep=False).sum())} max_repeat {vc.iloc[0]}')
    cross=v.groupby(v).apply(lambda s: tr.loc[s.index,'class'].nunique())
    cv=cross[cross>1].index
    print('  cross-class vectors',len(cv),'rows',tr[v.isin(cv)]['class'].value_counts().to_dict())
    m=tr['class']=='malicious'
    g=pd.DataFrame({'g':tr.splitGroup[m],'v':v[m]}).groupby('g').v.agg(['size','nunique']).sort_values('size',ascending=False).head(6)
    print(g.assign(ratio=lambda d:(d['size']/d['nunique']).round(1)).to_string())
    if name=='no_updateInterval':
        v6=d6[cols].agg('|'.join,axis=1)[d6.label=='1']
        print('  d06 malicious unique',v6.nunique(),'of',len(v6))
