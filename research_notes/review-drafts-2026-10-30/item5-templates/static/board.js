// HTML 폼은 PATCH·DELETE를 보낼 수 없어서, data-method가 붙은 폼과 버튼만 fetch로 보낸다.
// meta csrf-token이 있으면 X-CSRFToken 헤더로 함께 보낸다. 인라인 스크립트는 쓰지 않는다.
(function () {
  function token() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.getAttribute("content") : "";
  }

  function send(method, url, body) {
    var headers = { "Accept": "application/json" };
    var t = token();
    if (t) { headers["X-CSRFToken"] = t; }
    if (body) { headers["Content-Type"] = "application/json"; }
    return fetch(url, {
      method: method,
      headers: headers,
      body: body ? JSON.stringify(body) : undefined,
      credentials: "same-origin"
    });
  }

  function done(res, next) {
    if (!res.ok) { alert("요청이 실패했습니다 " + res.status); return; }
    if (next) { location.assign(next); } else { location.reload(); }
  }

  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!form.dataset || !form.dataset.method) { return; }
    e.preventDefault();
    var body = {};
    new FormData(form).forEach(function (v, k) {
      if (typeof v === "string") { body[k] = v; }
    });
    send(form.dataset.method, form.dataset.url, body)
      .then(function (r) { done(r, form.dataset.next); });
  });

  document.addEventListener("click", function (e) {
    var btn = e.target.closest("button[data-method]");
    if (!btn || btn.form) { return; }
    if (btn.dataset.confirm && !confirm(btn.dataset.confirm)) { return; }
    send(btn.dataset.method, btn.dataset.url, null)
      .then(function (r) { done(r, btn.dataset.next); });
  });
})();
