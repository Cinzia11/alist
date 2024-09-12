import{h as e,ag as O,aj as _,a9 as y,Q as i,V as l,bD as T,a_ as I,ak as h,bZ as P,cg as k,a as b,r as d,ch as x,W as v,af as $,a7 as L,B as m,ab as S,t as D,ac as A,c8 as f,S as g,at as j,a2 as w,cb as V,y as R,ci as C,E as o,G as a,cc as M,cj as z,d as F,b5 as B,K as W,N as H,ad as U}from"./index.afc5cbef.js";import{g as X,O as c}from"./icon.bcadb4b9.js";import{m as G}from"./index.69ee4e7e.js";import{T as K}from"./Layout.53ea9934.js";const N=r=>e(l,{class:"fileinfo",py:"$6",spacing:"$6",get children(){return[e(O,{boxSize:"$20",get fallback(){return e(_,{get color(){return y()},boxSize:"$20",get as(){return X(i.obj)}})},get src(){return i.obj.thumb}}),e(l,{spacing:"$2",get children(){return[e(T,{size:"lg",css:{wordBreak:"break-all"},get children(){return i.obj.name}}),e(I,{color:"$neutral10",size:"sm",get children(){return[h(()=>P(i.obj.size))," \xB7 ",h(()=>k(i.obj.modified))]}})]}}),e(l,{spacing:"$2",get children(){return r.children}})]}}),E=()=>{const r=b(),n=d(()=>x(i.obj.name)),{currentObjLink:s}=v();return e(g,{get when(){return n().length},get children(){return e($,{get children(){return[e(L,{as:m,colorScheme:"success",get rightIcon(){return e(_,{as:G})},get children(){return r("home.preview.open_with")}}),e(S,{get children(){return e(D,{get each(){return n()},children:t=>e(A,{as:"a",target:"_blank",get href(){return f(t.value,{raw_url:i.raw_url,name:i.obj.name,d_url:s(!0)})},get children(){return t.key}})})}})]}})}})},p=r=>{const n=b(),{copyCurrentRawLink:s}=j();return e(N,{get children(){return[e(w,{spacing:"$2",get children(){return[e(m,{colorScheme:"accent",onClick:()=>s(!0),get children(){return n("home.toolbar.copy_link")}}),e(m,{as:"a",get href(){return i.raw_url},target:"_blank",get children(){return n("home.preview.download")}})]}}),e(g,{get when(){return r.openWith},get children(){return e(E,{})}})]}})},Q=Object.freeze(Object.defineProperty({__proto__:null,Download:p,default:p},Symbol.toStringTag,{value:"Module"})),Z=r=>{const{currentObjLink:n}=v(),s=d(()=>f(r.scheme,{raw_url:i.raw_url,name:i.obj.name,d_url:n(!0)}));return e(C,{w:"$full",h:"70vh",get children(){return[e(V.iframe,{w:"$full",h:"$full",get src(){return s()}}),e(_,{pos:"absolute",right:"$2",bottom:"$10","aria-label":"Open in new tab",as:K,onClick:()=>{window.open(s(),"_blank")},cursor:"pointer",rounded:"$md",get bgColor(){return R()},p:"$1",boxSize:"$7"})]}})},q=r=>()=>e(Z,{scheme:r}),J=[{name:"HTML render",exts:["html"],component:o(()=>a(()=>import("./html.6030b46e.js"),["assets/html.6030b46e.js","assets/index.afc5cbef.js","assets/index.15d8d646.css"]))},{name:"Aliyun Video Previewer",type:c.VIDEO,provider:/^Aliyundrive(Open)?$/,component:o(()=>a(()=>import("./aliyun_video.976535a2.js"),["assets/aliyun_video.976535a2.js","assets/index.afc5cbef.js","assets/index.15d8d646.css","assets/icon.bcadb4b9.js","assets/index.09dc6b85.js","assets/index.69ee4e7e.js","assets/Layout.53ea9934.js","assets/index.7bba5123.js","assets/FolderTree.e40c5364.js","assets/video_box.6c50e108.js","assets/hls.acdc0631.js"]))},{name:"Markdown",type:c.TEXT,component:o(()=>a(()=>import("./markdown.963b0074.js"),["assets/markdown.963b0074.js","assets/index.afc5cbef.js","assets/index.15d8d646.css"]))},{name:"Markdown with word wrap",type:c.TEXT,component:o(()=>a(()=>import("./markdown_with_word_wrap.2e2a9c71.js"),["assets/markdown_with_word_wrap.2e2a9c71.js","assets/index.afc5cbef.js","assets/index.15d8d646.css"]))},{name:"Url Open",exts:["url"],component:o(()=>a(()=>import("./url.2dddca32.js"),["assets/url.2dddca32.js","assets/index.afc5cbef.js","assets/index.15d8d646.css","assets/icon.bcadb4b9.js","assets/index.09dc6b85.js","assets/index.69ee4e7e.js","assets/Layout.53ea9934.js","assets/index.7bba5123.js","assets/FolderTree.e40c5364.js"]))},{name:"Text Editor",type:c.TEXT,exts:["url"],component:o(()=>a(()=>import("./text-editor.bc98e3a2.js"),["assets/text-editor.bc98e3a2.js","assets/index.afc5cbef.js","assets/index.15d8d646.css"]))},{name:"Image",type:c.IMAGE,component:o(()=>a(()=>import("./image.d20a10bb.js"),["assets/image.d20a10bb.js","assets/index.afc5cbef.js","assets/index.15d8d646.css","assets/ImageWithError.602df38d.js"]))},{name:"Video",type:c.VIDEO,component:o(()=>a(()=>import("./video.b8486950.js"),["assets/video.b8486950.js","assets/index.afc5cbef.js","assets/index.15d8d646.css","assets/icon.bcadb4b9.js","assets/index.09dc6b85.js","assets/index.69ee4e7e.js","assets/Layout.53ea9934.js","assets/index.7bba5123.js","assets/FolderTree.e40c5364.js","assets/video_box.6c50e108.js","assets/hls.acdc0631.js"]))},{name:"Audio",type:c.AUDIO,component:o(()=>a(()=>import("./audio.791c2686.js"),["assets/audio.791c2686.js","assets/audio.e5b5af14.css","assets/index.afc5cbef.js","assets/index.15d8d646.css","assets/icon.bcadb4b9.js","assets/index.09dc6b85.js","assets/index.69ee4e7e.js","assets/Layout.53ea9934.js","assets/index.7bba5123.js","assets/FolderTree.e40c5364.js"]))},{name:"Ipa",exts:["ipa","tipa"],component:o(()=>a(()=>import("./ipa.c24de6bc.js"),["assets/ipa.c24de6bc.js","assets/index.afc5cbef.js","assets/index.15d8d646.css","assets/icon.bcadb4b9.js","assets/index.09dc6b85.js","assets/index.69ee4e7e.js","assets/Layout.53ea9934.js","assets/index.7bba5123.js","assets/FolderTree.e40c5364.js"]))},{name:"Plist",exts:["plist"],component:o(()=>a(()=>import("./plist.fe11fda0.js"),["assets/plist.fe11fda0.js","assets/index.afc5cbef.js","assets/index.15d8d646.css","assets/icon.bcadb4b9.js","assets/index.09dc6b85.js","assets/index.69ee4e7e.js","assets/Layout.53ea9934.js","assets/index.7bba5123.js","assets/FolderTree.e40c5364.js"]))},{name:"Aliyun Office Previewer",exts:["doc","docx","ppt","pptx","xls","xlsx","pdf"],provider:/^Aliyundrive(Share)?$/,component:o(()=>a(()=>import("./aliyun_office.c72e35c6.js"),["assets/aliyun_office.c72e35c6.js","assets/index.afc5cbef.js","assets/index.15d8d646.css"]))}],Y=r=>{const n=[];return J.forEach(t=>{var u;t.provider&&!t.provider.test(r.provider)||(t.type===r.type||t.exts==="*"||((u=t.exts)==null?void 0:u.includes(M(r.name).toLowerCase())))&&n.push({name:t.name,component:t.component})}),z(r.name).forEach(t=>{n.push({name:t.key,component:q(t.value)})}),n.push({name:"Download",component:o(()=>a(()=>Promise.resolve().then(()=>Q),void 0))}),n},ee=()=>{const r=d(()=>Y({...i.obj,provider:i.provider})),[n,s]=F(r()[0]);return e(g,{get when(){return r().length>1},get fallback(){return e(p,{openWith:!0})},get children(){return e(l,{w:"$full",spacing:"$2",get children(){return[e(w,{w:"$full",spacing:"$2",get children(){return[e(B,{alwaysShowBorder:!0,get value(){return n().name},onChange:t=>{s(r().find(u=>u.name===t))},get options(){return r().map(t=>({value:t.name}))}}),e(E,{})]}}),e(W,{get fallback(){return e(H,{})},get children(){return e(U,{get component(){return n().component}})}})]}})}})},ae=Object.freeze(Object.defineProperty({__proto__:null,default:ee},Symbol.toStringTag,{value:"Module"}));export{N as F,ae as a};
