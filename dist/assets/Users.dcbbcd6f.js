import{a as _,b as U,aP as B,b2 as u,d as v,cw as p,h as e,a2 as h,B as o,Y as T,cx as x,cy as P,cz as b,t as m,cA as f,cB as F,cC as s,b3 as g,n as $,V as R,bY as z,aq as D,as as H,a4 as I}from"./index.afc5cbef.js";import{n as L}from"./index.09dc6b85.js";import{D as M}from"./DeletePopover.f7bb98a1.js";import{W as V}from"./Wether.c241d3b7.js";const W=n=>{const t=[{name:"general",color:"info"},{name:"guest",color:"neutral"},{name:"admin",color:"accent"}];return e(z,{get colorScheme(){return t[n.role].color},get children(){return t[n.role].name}})},Y=n=>{const t=_(),i=a=>`$${a?"success":"danger"}9`;return e(h,{spacing:"$0_5",get children(){return e(m,{each:D,children:(a,d)=>e(H,{get label(){return t(`users.permissions.${a}`)},get children(){return e(T,{boxSize:"$2",rounded:"$full",get bg(){return i(I.can(n.user,d()))}})}})})}})},j=()=>{const n=_();L("manage.sidemenu.users");const{to:t}=U(),[i,a]=B(()=>u.get("/admin/user/list")),[d,k]=v([]),l=async()=>{const r=await a();g(r,c=>k(c.content))};l();const[w,y]=p(r=>u.post(`/admin/user/delete?id=${r}`)),[C,S]=p(r=>u.post(`/admin/user/cancel_2fa?id=${r}`));return e(R,{spacing:"$2",alignItems:"start",w:"$full",get children(){return[e(h,{spacing:"$2",get children(){return[e(o,{colorScheme:"accent",get loading(){return i()},onClick:l,get children(){return n("global.refresh")}}),e(o,{onClick:()=>{t("/@manage/users/add")},get children(){return n("global.add")}})]}}),e(T,{w:"$full",overflowX:"auto",get children(){return e(x,{highlightOnHover:!0,dense:!0,get children(){return[e(P,{get children(){return e(b,{get children(){return[e(m,{each:["username","base_path","role","permission","available"],children:r=>e(f,{get children(){return n(`users.${r}`)}})}),e(f,{get children(){return n("global.operations")}})]}})}}),e(F,{get children(){return e(m,{get each(){return d()},children:r=>e(b,{get children(){return[e(s,{get children(){return r.username}}),e(s,{get children(){return r.base_path}}),e(s,{get children(){return e(W,{get role(){return r.role}})}}),e(s,{get children(){return e(Y,{user:r})}}),e(s,{get children(){return e(V,{get yes(){return!r.disabled}})}}),e(s,{get children(){return e(h,{spacing:"$2",get children(){return[e(o,{onClick:()=>{t(`/@manage/users/edit/${r.id}`)},get children(){return n("global.edit")}}),e(M,{get name(){return r.username},get loading(){return w()===r.id},onClick:async()=>{const c=await y(r.id);g(c,()=>{$.success(n("global.delete_success")),l()})}}),e(o,{colorScheme:"accent",get loading(){return C()===r.id},onClick:async()=>{const c=await S(r.id);g(c,()=>{$.success(n("users.cancel_2fa_success")),l()})},get children(){return n("users.cancel_2fa")}})]}})}})]}})})}})]}})}})]}})};export{j as default};
