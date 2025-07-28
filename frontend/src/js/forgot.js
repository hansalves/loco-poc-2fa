import van from "/js/van/van.js";

const {form, input, div, span, h1, label} = van.tags;

function Forgot() {
	const emailInput = input({name: "email", type: "text", id: crypto.randomUUID()});

	const msg = van.state("");

	const loginForm = form(
		{onsubmit: submit},
		div({class: "m-2"}, label({for: emailInput.id, class: "inline-block w-48"}, "email"), emailInput),
		div({class: "m-2"}, span({class: "inline-block w-48"}), input({type: "submit", value: "Submit"})),
		div({class: "m-2"}, span(msg))
	);

	function submit(evt) {
		evt.preventDefault();
		evt.stopPropagation();
		msg.val = "";
		const formData = new FormData(loginForm);
		const requestBody = JSON.stringify(Object.fromEntries(formData));
		fetch("/api/auth/forgot", {
			method: "POST",
			body: requestBody,
			headers: {
				"Content-Type": "application/json",
			},
		})
			.then(async (res) => {
				if (res.status === 200) {
					msg.val = "Check your email";
				} else {
					msg.val = "Something went wrong!";
				}
			})
			.catch((e) => {
				console.error(e);
				msg.val = "Something went wrong!";
			});
	}

	return div({class: "p-5"}, h1("login"), div({class: "border rounded-lg p-2"}, loginForm));
};

document.addEventListener("DOMContentLoaded", () => {
	van.add(document.body, Forgot());
});
