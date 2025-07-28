import van from "/js/van/van.js";
import LoadingIndicator from "/js/components/loading-indicator.js";

const {form, input, div, span, h1, label, a, button} = van.tags;

function Login() {
	const emailInput = input({name: "email", type: "text", id: crypto.randomUUID()});
	const linkEmailInput = input({name: "email", type: "text", id: crypto.randomUUID()});
	const passwordInput = input({name: "password", type: "password", id: crypto.randomUUID()});
	const totpInput = input({name: "totp", type: "text", id: crypto.randomUUID()});

	let email = "";
	let totp_login_token = "";

	const status = van.state("login");
	const loginMsg = van.state("");
	const loginSpan = span(loginMsg);
	// these derives are required because the msg state loses its binding when the form is not in the dom
	van.derive(() => {
		loginSpan.textContent = loginMsg.val;
	});
	const totpMsg = van.state("");
	const totpSpan = span(totpMsg);
	van.derive(() => {
		totpSpan.textContent = totpMsg.val;
	});
	const linkMsg = van.state("");
	const linkSpan = span(linkMsg);
	van.derive(() => {
		linkSpan.textContent = linkMsg.val;
	});
	const loading = van.state(false);

	const loginForm = form(
		{onsubmit: submitLogin},
		div({class: "m-2"}, label({for: emailInput.id, class: "inline-block w-48"}, "email"), emailInput),
		div({class: "m-2"}, label({for: passwordInput.id, class: "inline-block w-48"}, "password"), passwordInput),
		div({class: "m-2"}, span({class: "inline-block w-48"}), input({type: "submit", value: "Login", class: "btn"})),
		div({class: "m-2"}, loginSpan)
	);

	const totpForm = form(
		{onsubmit: submitTOTP},
		div({class: "m-2"}, "To finish logging in, please enter the 2FA code from your authenticator app."),
		div({class: "m-2"}, label({for: totpInput.id, class: "inline-block w-48"}, "2FA Code"), totpInput),
		div({class: "m-2"}, span({class: "inline-block w-48"}), input({type: "submit", value: "Login", class: "btn"})),
		div({class: "m-2"}, totpSpan)
	);

	const magicLinkForm = form(
		{onsubmit: submitMagicLink},
		div({class: "m-2"}, label({for: linkEmailInput.id, class: "inline-block w-48"}, "email"), linkEmailInput),
		div(
			{class: "m-2"},
			span({class: "inline-block w-48"}),
			input({type: "submit", value: "Send login email", class: "btn"})
		),
		div({class: "m-2"}, linkSpan)
	);

	const forgotA = a(
		{
			href: "/forgot",
		},
		"Forgot password"
	);

	function handleLogin(data) {
		for (const [key, value] of Object.entries(data)) {
			sessionStorage[key] = value;
		}
		loginMsg.val = "Logged in";
		totpMsg.val = "Logged in";
		return new Promise((resolve) => {
			setTimeout(() => {
				resolve();
				window.location.href = "/";
			}, 1000);
		});
	}

	function submitLogin(evt) {
		evt.preventDefault();
		evt.stopPropagation();
		const formData = new FormData(loginForm);
		const requestBody = JSON.stringify(Object.fromEntries(formData));
		email = emailInput.value;
		loading.val = true;
		loginMsg.val = "Logging in...";
		fetch("/api/auth/login", {
			method: "POST",
			body: requestBody,
			headers: {
				"Content-Type": "application/json",
			},
		})
			.then(async (res) => {
				console.log("login returned", res.status);
				if (res.status === 200) {
					const data = await res.json();
					if (data.type === "Login") {
						return handleLogin(data);
					} else if (data.type === "TOTPChallenge") {
						status.val = "TOTPChallenge";
						totp_login_token = data.totp_login_token;
					}
				} else if (res.status === 401) {
					loginMsg.val = "Invalid username or password";
				} else {
					loginMsg.val = "Something went wrong!";
				}
				return Promise.resolve();
			})
			.catch((e) => {
				console.error(e);
				loginMsg.val = "Something went wrong!";
			})
			.finally(() => {
				loading.val = false;
			});
	}
	function submitMagicLink(evt) {
		evt.preventDefault();
		evt.stopPropagation();
		const formData = new FormData(magicLinkForm);
		const requestBody = JSON.stringify(Object.fromEntries(formData));
		loading.val = true;
		fetch("/api/auth/magic-link", {
			method: "POST",
			body: requestBody,
			headers: {
				"Content-Type": "application/json",
			},
		})
			.then(async (res) => {
				if (res.status === 200) {
					linkMsg.val = "Check your email";
				} else {
					linkMsg.val = "Something went wrong!";
				}
			})
			.catch((e) => {
				console.error(e);
				linkMsg.val = "Something went wrong!";
			})
			.finally(() => {
				loading.val = false;
			});
	}

	function submitTOTP(evt) {
		evt.preventDefault();
		evt.stopPropagation();
		const body = JSON.stringify({email, token: totp_login_token, totp: totpInput.value});
		loading.val = true;
		fetch("/api/auth/login-totp", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
			},
			body,
		})
			.then(async (res) => {
				if (res.status === 200) {
					const data = await res.json();
					totpMsg.val = "Logged in";
					return handleLogin(data);
				} else if (res.status === 401) {
					const data = await res.json();
					totpMsg.val = data.description;
				} else {
					totpMsg.val = "Something went wrong!";
				}
			})
			.catch((e) => {
				console.error(e);
				totpMsg.val = "Something went wrong!";
			})
			.finally(() => {
				loading.val = false;
			});
	}

	return div(
		{class: "p-5"},
		h1("login"),
		() => (loading.val ? LoadingIndicator() : div()),
		div(
			{class: "border rounded-lg p-2 my-2"},
			() => (status.val === "login" ? loginForm : div()),
			() => (status.val === "TOTPChallenge" ? totpForm : div()),
			div({class: "text-center"}, forgotA)
		),
		() => (status.val === "login" ? div({class: "border rounded-lg p-2 my-2"}, magicLinkForm) : div())
	);
}

document.addEventListener("DOMContentLoaded", () => {
	van.add(document.body, Login());
});
