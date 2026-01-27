# Contributing to PEAT

Thank you for your interest in contributing to PEAT! We welcome contributions from everyone and appreciate your efforts to improve our project. This guide will help you understand how to contribute effectively.

> Note: A failure to follow this guide will result in delay of PRs until there is compliance.

## Table of Contents

- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
  - [Reporting Issues](#reporting-issues)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Submitting Code](#submitting-code)
- [License](#license)

## Getting Started

1. **Fork the Repository**: Click the "Fork" button at the top right of the repository page to create your own copy of the project.

2. **Clone Your Fork**: Clone your forked repository to your local machine using:

   ```bash
   git clone https://github.com/<your-username>/peat.git
   ```

3. **Set Upstream Remote**: Add the original repository as an upstream remote to keep your fork up to date:

    ```bash
    git remote add upstream https://github.com/sandialabs/peat.git
    ```

4. **(Optional) Update Your Fork with Upstream**: To keep your fork up to date with the original repository, follow these steps:
    - Fetch the latest changes from the upstream repository

        ```bash
        git fetch upstream
        ```

    - Merge the changes from the upstream main branch into your local main branch

        ```bash
        git checkout main
        git merge upstream/main
        ```

    - Push the updated main branch to your forked repository

        ```bash
        git push origin main
        ```

## How to Contribute

### Reporting Issues

If you encounter a bug or have a feature request, please open an issue in the [Issues](https://github.com/sandialabs/PEAT/issues) section. Be sure to include:

- A clear description of the issue.
- Steps to reproduce the issue.
- Any relevant screenshots or logs.

### Suggesting Enhancements

We welcome suggestions for improvements! Please open an [issue](https://github.com/sandialabs/PEAT/issues) or a [discussion](https://github.com/sandialabs/PEAT/discussions) to discuss your ideas before implementing them. You are also welcome to implement the idea and open a Pull Request, however be aware that there is a risk your idea may be rejected.

### Submitting Code

1. **Create a Branch**: Create a new branch (on your fork of the repository) for your feature or bug fix using [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) notation. The branch name should follow this format:

    ```bash
    type/description
    ```

    Where `type` can be one of the following:
    - `feat`: A new feature
    - `fix`: A bug fix
    - `docs`: Documentation only changes
    - `style`: Changes that do not affect the meaning of the code (white-space, formatting, etc.)
    - `refactor`: A code change that neither fixes a bug nor adds a feature
    - `test`: Adding missing tests or correcting existing tests
    - `chore`: Changes to the build process or auxiliary tools and libraries

    Example:

    ```bash
    git checkout -b feat/add-user-authentication
    ```

1. **Make Your Changes**: Implement your changes, and ensure the following requirements are followed:

    - All changes MUST pass linting checks and CI (GitHub Actions). This includes formatting checks. Formatting is automated and does NOT need to be done manually. To format code and check for linting issues, run the following commands:

    ```shell
    pdm run format
    pdm run lint
    ```

    - All contributions MUST be in English
    - Changes SHOULD have basic tests implemented. These tests should be called from the CI pipeline (this is the case if unit tests are placed in `tests/`).
    - Changes SHOULD be commented to a reasonable extent, especially in areas where the data or knowledge required is not readily available or obvious. There SHOULD be docstrings in the majority of functions and classes added.
    - Type annotations SHOULD be used for function arguments, function return values, and class attributes.
    - TODO comments are permitted, but discouraged. If the TODO is significant, [open a issue](https://github.com/sandialabs/PEAT/issues) on GitHub or start a [discussion](https://github.com/sandialabs/PEAT/discussions).
    - Docstrings should follow [PEP-257](https://peps.python.org/pep-0257/).

1. **Stage Your Changes**: Use the `git add` command to stage the changes you want to commit. You can stage specific files or all changes:
    To stage specific files:

    ```bash
    git add path/to/your/file1 path/to/your/file2
    ```

    To stage all changes:

    ```bash
    git add .
    ```

1. **Commit Your Changes**: Commit your changes using [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) notation. Your commit message should follow this format:

    ```bash
    type(scope): subject
    ```

    - **Scope** is optional and can be used to indicate the area of the codebase affected by the change.
    - **Subject** should be a short description of the change.

    Example:

    ```bash
    git commit -m "feat(auth): add user authentication feature"
    ```

    If you need to write a longer commit message, you can do so by running `git commit`. This will open your default text editor where you can write a detailed commit message. The first line should be a brief summary conforming to the format above, followed by a blank line, and then a more detailed explanation.

    Example:

    ```bash
    feat(auth): add user authentication feature

    This commit introduces a new authentication system that allows users to log in using their email and password. It also includes validation for user input and error handling.
    ```

1. **Rebase Your Branch**: Before opening a pull request, ensure your branch is up to date with the main branch.
    - Fetch the latest changes from the upstream repository.

        ```bash
        git fetch upstream
        ```

    - Rebase your branch into the main branch to preserve a linear history. Resolve any conflicts that may arise during the rebase process.

        ```bash
        git rebase upstream/main
        ```

    - (Optional) If you have multiple commits that you want to combine into a single commit, you can use interactive rebase. In the interactive rebase interface, change the word `pick` to `squash` (or `s`) for all commits you want to combine into the first commit. After saving and closing the editor, you will be prompted to create a new commit message. Write a single, comprehensive commit message that summarizes all the changes.

        ```bash
        git rebase -i upstream/main
        ```

1. **Push to Your Fork**: If you had to rebase, you may need to force push your changes to your forked repository.

    Example:

    ```bash
    git push origin feat/add-user-authentication --force
    ```

1. **Open a Pull Request**: Go to the original repository and open a [pull request](https://github.com/sandialabs/peat/pulls). Provide a clear description of your changes and reference any related issues.

1. **(Optional) Request review from relevant maintainers**: All pull requests must be approved by at least one maintainer. If you know which maintainers would best understand you contribution, request their review by clicking on "Reviewers" on the right side of the PR screen.

## License

By contributing to this project, you agree that your contributions will be licensed under the [GNU](https://github.com/sandialabs/peat/blob/main/LICENSE) License.
