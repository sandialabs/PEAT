import yaml
from textual import on
from textual.app import App, ComposeResult
from textual.containers import HorizontalGroup, VerticalGroup, VerticalScroll
from textual.reactive import reactive
from textual.screen import Screen
from textual.types import NoSelection
from textual.widgets import Button, Collapsible, Footer, Header, Input, Label, Select

from peat.api.config_builder_api import (
    generate_simple_config,
    get_default_options,
    get_modules,
    get_pull_methods,
)


class PullMethod(HorizontalGroup):
    module = ""
    pull_methods = []
    selected_pull_method = reactive("")
    parent_host = None

    def compose(self) -> ComposeResult:
        yield Button("Delete Pull Method", id="deletepullmethod", variant="error")
        yield Select(
            [(pull_method, index + 1) for index, pull_method in enumerate(self.pull_methods)]
        )
        pull_fields = [
            HorizontalGroup(Label("username"), Input(placeholder="username", id="username")),
            HorizontalGroup(Label("password"), Input(placeholder="password", id="password")),
            HorizontalGroup(Label("port"), Input(placeholder="22", id="port")),
        ]

        yield VerticalGroup(*pull_fields)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "deletepullmethod":
            self.parent_host.delete_pull_method(self)
            self.remove()

    @on(Select.Changed)
    def select_changed(self, event: Select.Changed) -> None:
        if not isinstance(event.value, NoSelection):
            self.selected_pull_method = str(self.pull_methods[event.value - 1])
            default_options = get_default_options(self.module)
            try:
                self.query_one("#username").placeholder = default_options[
                    self.selected_pull_method
                ]["user"]
                self.query_one("#password").placeholder = default_options[
                    self.selected_pull_method
                ]["pass"]
                self.query_one("#port").placeholder = default_options[self.selected_pull_method][
                    "port"
                ]
            except Exception:
                pass
        else:
            self.selected_pull_method = ""


class Host(HorizontalGroup):
    ip = ""
    name = ""
    module = ""

    parent_app = None

    pull_methods = []
    pull_methods_collapsible = None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "addpullmethod":
            new_pull_method = PullMethod()
            available_pull_methods = get_pull_methods(self.module)
            if available_pull_methods is not None:
                new_pull_method.pull_methods = available_pull_methods
            new_pull_method.parent_host = self
            new_pull_method.module = self.module
            self.pull_methods = [*self.pull_methods, new_pull_method]
            self.query_one("#pull_methods").mount(new_pull_method)

            self.pull_methods_collapsible.title = (
                str(len(self.pull_methods))
                + " Pull Methods: "
                + ", ".join(
                    [pull_method.selected_pull_method for pull_method in self.pull_methods]
                )
            )

        if button_id == "deletehost":
            self.parent_app.remove_host(self)
            self.remove()

    def compose(self) -> ComposeResult:
        yield Label(
            "Host: " + self.name + "\n" + "IP: " + self.ip + "\n" + "Module: " + self.module,
            id="hostinfo",
        )

        self.pull_methods_collapsible = Collapsible(
            title=str(len(self.pull_methods))
            + " Pull Methods: "
            + ", ".join([pull_method.selected_pull_method for pull_method in self.pull_methods])
        )
        with self.pull_methods_collapsible:
            yield VerticalScroll(*self.pull_methods, id="pull_methods")

        yield Button("Add Pull Method", id="addpullmethod", variant="success")
        yield Button("Delete Host", id="deletehost", variant="error")

    @on(Select.Changed)
    def select_changed(self) -> None:
        self.pull_methods_collapsible.title = (
            str(len(self.pull_methods))
            + " Pull Methods: "
            + ", ".join([pull_method.selected_pull_method for pull_method in self.pull_methods])
        )

    # Requires changing self list reference to force UI update
    def delete_pull_method(self, pull_method):
        self.pull_methods.remove(pull_method)
        self.pull_methods_collapsible.title = (
            str(len(self.pull_methods))
            + " Pull Methods: "
            + ", ".join([pull_method.selected_pull_method for pull_method in self.pull_methods])
        )


class ConfigPreview(Screen):
    BINDINGS = [
        ("escape", "app.pop_screen", "Exit Preview"),
        ("v", "app.pop_screen", "Exit Preview"),
    ]

    def __init__(self, config: str, **kwargs):
        super().__init__(**kwargs)
        self.config = config

    def compose(self) -> ComposeResult:
        yield Label("Press ESC to exit preview.\n--------------------------\n")
        yield Label(self.config)


class PEATBuilder(App):
    # CSS_PATH = "peatbuilder.tcss"
    # SCREENS = {"config": Config}
    CSS = """
    #ip_input {
        width: 30
    }
    #name_input {
        width: 30
    }
    """
    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("v", "view_config", "View config"),
        ("s", "save_config", "Save config"),
    ]

    host_data = []
    modules = get_modules()

    def compose(self) -> ComposeResult:
        yield Header()
        yield VerticalScroll(*self.host_data, id="hosts")
        yield HorizontalGroup(
            Button("Add Host", id="addhost", variant="primary"),
            Label("IP: "),
            Input(placeholder="192.168.1.1", id="ip_input"),
            Label("Name: "),
            Input(placeholder="device", id="name_input"),
            Label("Module: "),
            Select(
                [(pull_method, index + 1) for index, pull_method in enumerate(self.modules)],
                id="module_input",
            ),
        )
        yield Input(placeholder="output_filename.yaml", id="filename")
        yield Footer()

    def generate_config(self) -> str:
        peat_hosts = [(host.ip, host.name, host.module) for host in self.host_data]
        config = yaml.safe_load(generate_simple_config(peat_hosts))
        for index, host in enumerate(self.host_data):
            if config["hosts"][index]["options"] is not None:
                enabled_methods = []
                for pull_method in host.pull_methods:
                    if pull_method.selected_pull_method in config["hosts"][index]["options"]:
                        if (
                            "user"
                            in config["hosts"][index]["options"][pull_method.selected_pull_method]
                        ):
                            config["hosts"][index]["options"][pull_method.selected_pull_method][
                                "user"
                            ] = pull_method.query_one("#username").value
                        if (
                            "pass"
                            in config["hosts"][index]["options"][pull_method.selected_pull_method]
                        ):
                            config["hosts"][index]["options"][pull_method.selected_pull_method][
                                "pass"
                            ] = pull_method.query_one("#password").value
                        if (
                            "port"
                            in config["hosts"][index]["options"][pull_method.selected_pull_method]
                        ):
                            config["hosts"][index]["options"][pull_method.selected_pull_method][
                                "port"
                            ] = pull_method.query_one("#port").value
                        enabled_methods.append(pull_method.selected_pull_method)
                for template_pull_method in list(config["hosts"][index]["options"].keys()):
                    if template_pull_method not in enabled_methods:
                        try:
                            config["hosts"][index]["options"][host.module.lower()][
                                "pull_methods"
                            ].remove(template_pull_method)
                            del config["hosts"][index]["options"][template_pull_method]
                        except Exception:
                            # Improperly formatted default options in a PEAT module
                            pass
            else:
                del config["hosts"][index]["options"]
        return config

    def action_view_config(self) -> None:
        config = self.generate_config()
        self.push_screen(ConfigPreview(yaml.dump(config)))

    def action_save_config(self) -> None:
        config = self.generate_config()
        filename = self.query_one("#filename").value
        if filename == "":
            filename = "peat_config.yaml"

        with open(filename, "w") as yaml_file:
            yaml_file.write(yaml.dump(config))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "addhost":
            new_host = Host()
            new_host.ip = self.query_one("#ip_input").value
            new_host.name = self.query_one("#name_input").value
            module_input = self.query_one("#module_input").value
            if not isinstance(module_input, NoSelection):
                new_host.module = self.modules[module_input - 1]
            new_host.parent_app = self
            self.host_data = [*self.host_data, new_host]
            self.query_one("#hosts").mount(new_host)
            new_host.scroll_visible()

    # Requires changing self list reference to force UI update
    def remove_host(self, host):
        new_host_data = self.host_data.copy()
        new_host_data.remove(host)
        self.host_data = new_host_data

    def action_toggle_dark(self) -> None:
        self.theme = "textual-dark" if self.theme == "textual-light" else "textual-light"


def launch_builder():
    app = PEATBuilder()
    app.run()


if __name__ == "__main__":
    app = PEATBuilder()
    app.run()
