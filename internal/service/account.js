"use strict";
let access = "", refresh = "", challenge = "", enrollment = "";
const fragment = new URLSearchParams(location.hash.slice(1));
history.replaceState(null, "", location.pathname);
const form = document.querySelector("form"), status = document.querySelector("#status");
const value = name => form.elements.namedItem(name).value;
async function call(path, body, method = "POST") {
 const result = await fetch("/api/v1/auth/" + path, {method, credentials: "omit", headers: {"Content-Type": "application/json", ...(access ? {Authorization: "Bearer " + access} : {})}, ...(method === "GET" ? {} : {body: JSON.stringify(body || {})})});
 const json = await result.json(); if (!result.ok) throw Error(json.error || "Request failed"); return json.data;
}
function credentials(data) { if (data.access_token) {access = data.access_token; refresh = data.refresh_token; challenge = "";} }
function button(id, fn) {document.querySelector("#"+id).addEventListener("click",async()=>{try {const data=await fn(); credentials(data); status.textContent=data.message || "Done";} catch(e){status.textContent=e.message;}});}
button("login", async()=>{const data = challenge ? await call("mfa/verify", {token:challenge, code:value("code"),recovery_code:value("recovery_code")}) : await call("login", {tenant:value("tenant"),email:value("email"),password:value("password")}); if(data.mfa_required){challenge=data.challenge;return {message:"Enter your authenticator code and select Sign in again."};} form.elements.namedItem("password").value="";if(data.mfa_enrollment_required)data.message="MFA re-enrollment is required. Enter your password and select Set up MFA.";return data;});
button("register",()=>call("register",{tenant:value("tenant"),email:value("email"),password:value("password")}));
button("forgot",()=>call("forgot-password",{tenant:value("tenant"),email:value("email")}));
button("verify-resend",()=>call("resend-verification",{tenant:value("tenant"),email:value("email")}));
button("complete",async()=>{const action=fragment.get("action");const path={verify:"verify-email",reset:"reset-password",invite:"invitations/accept"}[action];if(!path)throw Error("Open the link from your account email first.");const data=await call(path,{token:fragment.get("token"),...(action==="verify"?{}:{new_password:value("new_password")})});fragment.delete("token");form.elements.namedItem("password").value="";return data;});
button("me",async()=>{try{const data=await call("me",null,"GET");document.querySelector("#identity").textContent=JSON.stringify(data,null,2);return data;}catch(e){if(!refresh)throw e;credentials(await call("refresh",{refresh_token:refresh}));const data=await call("me",null,"GET");document.querySelector("#identity").textContent=JSON.stringify(data,null,2);return data;}});
button("logout",async()=>{try{return await call("logout",{refresh_token:refresh});}finally{clearCredentials();document.querySelector("#identity").textContent="";document.querySelector("#security").textContent="";}});

const security = document.querySelector("#security");
async function proof() {return (await call("step-up",{password:value("password"),code:value("code"),recovery_code:value("recovery_code")})).proof;}
function clearCredentials() {access="";refresh="";challenge="";enrollment="";form.elements.namedItem("password").value="";form.elements.namedItem("new_password").value="";form.elements.namedItem("recovery_code").value="";}
button("setup",async()=>{const data=await call("mfa/setup",{proof:await proof()});enrollment=data.enrollment_token;security.textContent="Add this secret to your authenticator: "+data.secret+"\nThen enter its code and select Confirm MFA setup. This setup expires in ten minutes.";return {message:"Pending setup created. Your active factor is preserved."};});
button("confirm",async()=>{if(!enrollment)throw Error("Start MFA setup in this tab first.");const data=await call("mfa/confirm",{token:enrollment,code:value("code")});clearCredentials();security.textContent="Save these recovery codes once:\n"+data.recovery_codes.join("\n");return data;});
button("disable",async()=>{const data=await call("mfa/disable",{proof:await proof()});clearCredentials();security.textContent="";return data;});
button("change",async()=>{const data=await call("change-password",{proof:await proof(),new_password:value("new_password")});clearCredentials();return data;});
button("sessions",async()=>{const data=await call("sessions",null,"GET");security.textContent=JSON.stringify(data,null,2);return {message:"Your active sessions."};});
button("others",()=>call("sessions/revoke-others"));
button("revoke",()=>call("sessions/"+encodeURIComponent(value("session_id")),{},"DELETE"));
button("invite",async()=>{const data=await call("invitations",{email:value("invite_email"),proof:await proof()});form.elements.namedItem("invite_id").value=data.user_id;return {message:"Invitation queued for email delivery."};});
button("resend",async()=>call("invitations/"+encodeURIComponent(value("invite_id"))+"/resend",{proof:await proof()}));
button("cancel",async()=>call("invitations/"+encodeURIComponent(value("invite_id")),{proof:await proof()},"DELETE"));
button("clear",()=>{security.textContent="";return {message:"Displayed secrets cleared."};});
