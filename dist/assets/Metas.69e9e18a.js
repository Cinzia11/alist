import{a as $,b as k,aP as y,b2 as l,d as C,cw as M,h as e,a2 as o,B as c,Y as B,cx as S,cy as v,cz as d,t as g,cA as u,cB as x,cC as n,b3 as h,n as F,V as D}from"./index.afc5cbef.js";import{n as H}from"./index.09dc6b85.js";import{D as L}from"./DeletePopover.f7bb98a1.js";import{W as P}from"./Wether.c241d3b7.js";const A=()=>{const r=$();H("manage.sidemenu.metas");const{to:i}=k(),[p,m]=y(()=>l.get("/admin/meta/list")),[f,b]=C([]),a=async()=>{const t=await m();h(t,s=>b(s.content))};a();const[w,T]=M(t=>l.post(`/admin/meta/delete?id=${t}`));return e(D,{spacing:"$2",alignItems:"start",w:"$full",get children(){return[e(o,{spacing:"$2",get children(){return[e(c,{colorScheme:"accent",get loading(){return p()},onClick:a,get children(){return r("global.refresh")}}),e(c,{onClick:()=>{i("/@manage/metas/add")},get children(){return r("global.add")}})]}}),e(B,{w:"$full",overflowX:"auto",get children(){return e(S,{highlightOnHover:!0,dense:!0,get children(){return[e(v,{get children(){return e(d,{get children(){return[e(g,{each:["path","password","write"],children:t=>e(u,{get children(){return r(`metas.${t}`)}})}),e(u,{get children(){return r("global.operations")}})]}})}}),e(x,{get children(){return e(g,{get each(){return f()},children:t=>e(d,{get children(){return[e(n,{get children(){return t.path}}),e(n,{get children(){return t.password}}),e(n,{get children(){return e(P,{get yes(){return t.write}})}}),e(n,{get children(){return e(o,{spacing:"$2",get children(){return[e(c,{onClick:()=>{i(`/@manage/metas/edit/${t.id}`)},get children(){return r("global.edit")}}),e(L,{get name(){return t.path},get loading(){return w()===t.id},onClick:async()=>{const s=await T(t.id);h(s,()=>{F.success(r("global.delete_success")),a()})}})]}})}})]}})})}})]}})}})]}})};export{A as default};
