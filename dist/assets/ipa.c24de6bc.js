import{a as m,d as n,W as p,h as e,a2 as u,B as r,cX as g,cY as d,Q as a,cW as f}from"./index.afc5cbef.js";import{F as h}from"./File.35706d86.js";import"./icon.bcadb4b9.js";import"./index.09dc6b85.js";import"./index.69ee4e7e.js";import"./Layout.53ea9934.js";import"./index.7bba5123.js";import"./FolderTree.e40c5364.js";const v=()=>{const t=m(),[i,o]=n(!1),[s,l]=n(!1),{currentObjLink:c}=p();return e(h,{get children(){return e(u,{spacing:"$2",get children(){return[e(r,{as:"a",get href(){return`itms-services://?action=download-manifest&url=${g}/i/${d(encodeURIComponent(a.raw_url)+"/"+f(encodeURIComponent(a.obj.name)))}.plist`},onClick:()=>{o(!0)},get children(){return t(`home.preview.${i()?"installing":"install"}`)}}),e(r,{as:"a",colorScheme:"primary",get href(){return"apple-magnifier://install?url="+encodeURIComponent(c(!0))},onClick:()=>{l(!0)},get children(){return t(`home.preview.${s()?"tr-installing":"tr-install"}`)}})]}})}})};export{v as default};
