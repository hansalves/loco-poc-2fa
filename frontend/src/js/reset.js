import van from "/js/van/van.js";

const {form, input, div, span, h1, label, a} = van.tags;

function Reset() {
	const passwordInput = input({name: "password", type: "password", id: crypto.randomUUID()});

	const msg = van.state("");

	const loginForm = form(
		{onsubmit: submit},
		div({class: "m-2"}, label({for: passwordInput.id, class: "inline-block w-48"}, "password"), passwordInput),
		div({class: "m-2"}, input({type: "hidden", name: "token", value: (document.location.hash || "#").substring(1)})),
		div(
			{class: "m-2"},
			span({class: "inline-block w-48"}),
			input({type: "submit", value: "Submit", class: "btn"})
		),
		div({class: "m-2"}, span(msg))
	);

	function submit(evt) {
		evt.preventDefault();
		evt.stopPropagation();
		msg.val = "";
		const formData = new FormData(loginForm);
		const requestBody = JSON.stringify(Object.fromEntries(formData));
		fetch("/api/auth/reset", {
			method: "POST",
			body: requestBody,
			headers: {
				"Content-Type": "application/json",
			},
		})
			.then(async (res) => {
				if (res.status === 200) {
					msg.val = "Your password has been reset";
				} else {
					msg.val = "Something went wrong!";
				}
			})
			.catch((e) => {
				console.error(e);
				msg.val = "Something went wrong!";
			});
	}

	return div({class: "p-5"}, h1("Reset password"), div({class: "border rounded-lg p-2"}, loginForm));
}

document.addEventListener("DOMContentLoaded", () => {
	van.add(document.body, Reset());
});
