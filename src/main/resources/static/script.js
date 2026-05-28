// globals (yay vanilla javascript ftw)
fetchBlogs();
loginCheck();
document.getElementById("login-form")
    .addEventListener("submit", onLoginSubmit);
document.getElementById("logout-form")
    .addEventListener("submit", onLogoutSubmit);
document.getElementById("blog-form")
    .addEventListener("submit", onBlogSubmit);
let devToast = new bootstrap.Toast(
    document.getElementById("devToast"),
    { delay: 10000 }
);

function onLoginSubmit(event) {
  const username = event.target[0].value;
  const password = event.target[1].value;
  event.preventDefault();
  const csrfToken = getCookie("XSRF-TOKEN");
  fetch("/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "X-XSRF-TOKEN": csrfToken,
    },
    body: new URLSearchParams({username, password}),
  })
      .then(filterOk)
      .then(response => response.json())
      .then(user => window.sessionStorage.setItem("fullname", user.fullname))
      .then(() => loginCheck());
}

function onLogoutSubmit(event) {
  event.preventDefault();
  const csrfToken = getCookie("XSRF-TOKEN");
  fetch("/logout", {
    method: "POST",
    headers: { "X-XSRF-TOKEN": csrfToken },
  })
      .then(() => window.sessionStorage.removeItem("fullname"))
      .then(() => loginCheck());
}

function onBlogSubmit(event) {
  const data = {"title": event.target[0].value, "body": event.target[1].value};
  event.preventDefault();
  const csrfToken = getCookie("XSRF-TOKEN");
  fetch("/api/blog", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-XSRF-TOKEN": csrfToken,
    },
    body: JSON.stringify(data),
  })
      .then(filterOk)
      .then(() => fetchBlogs())
      .then(() => event.target.reset());
}

// switch display based on login status
function loginCheck() {
  const fullname = window.sessionStorage.getItem("fullname") || "anonymous";
  let authentic = fullname !== "anonymous";
  document.getElementById("login-form").parentElement.hidden = authentic;
  document.getElementById("logout-form").parentElement.hidden = !authentic;
  document.getElementById("username").innerText = fullname;
}

function fetchBlogs() {
  fetch("/api/blog")
      .then(filterOk)
      .then(response => response.json())
      .then(page => renderBlogs(page.content));
}

function renderBlogs(blogs) {
  const blogDiv = document.getElementById("blog-container");
  blogDiv.innerHTML = "" // clear
  for (const blog of blogs) {
    const titleEl = document.createElement("h2");
    titleEl.textContent = blog.title;
    const dateEl = document.createElement("p");
    dateEl.textContent = blog.createdAt;
    const bodyEl = document.createElement("p");
    bodyEl.textContent = blog.body;

    blogDiv.appendChild(titleEl);
    blogDiv.appendChild(dateEl);
    blogDiv.appendChild(bodyEl);
  }
}

function getCookie(name) {
  const encodedName = encodeURIComponent(name) + "=";
  const parts = document.cookie.split(";");
  for (const part of parts) {
    const c = part.trim();
    if (c.startsWith(encodedName)) {
      return decodeURIComponent(c.substring(encodedName.length));
    }
  }
  return "";
}

function showDevError(message) {
  document.getElementById("devToastText").textContent = message;
  devToast.show();
}

function filterOk(response) {
  if (response.ok) {
    return response;
  }
  return response.text().then(function(bodyText) {
    let msg = `HTTP ${response.status} ${response.statusText}\n${bodyText}`;
    if(msg.length > 1000){
      msg = msg.substring(0, 1000) + "\n...[truncated]";
    }
    showDevError(msg);
    throw response;
  });
}
