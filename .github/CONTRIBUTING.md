# Contributing to Capa

First off, thanks for taking the time to contribute!

The following is a set of guidelines for contributing to capa and its packages, which are hosted in the [Mandiant Organization](https://github.com/mandiant) on GitHub. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

#### Table Of Contents

[Code of Conduct](#code-of-conduct)

[What should I know before I get started?](#what-should-i-know-before-i-get-started)
  * [Capa and its Repositories](#capa-and-its-repositories)
  * [Capa Design Decisions](#design-decisions)

[How Can I Contribute?](#how-can-i-contribute)
  * [Reporting Bugs](#reporting-bugs)
  * [Suggesting Enhancements](#suggesting-enhancements)
  * [Your First Code Contribution](#your-first-code-contribution)
  * [Pull Requests](#pull-requests)

[Styleguides](#styleguides)
  * [Git Commit Messages](#git-commit-messages)
  * [Python Styleguide](#python-styleguide)
  * [Rules Styleguide](#rules-styleguide)

## Code of Conduct

This project and everyone participating in it is governed by the [Capa Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers.

## What should I know before I get started?

### Capa and its repositories

We host the capa project as three GitHub repositories:
  - [capa](https://github.com/mandiant/capa)
  - [capa-rules](https://github.com/mandiant/capa-rules)
  - [capa-testfiles](https://github.com/mandiant/capa-testfiles)
  
The command line tools, logic engine, and other Python source code are found in the `capa` repository.
This is the repository to fork when you want to enhance the features, performance, or user interface of capa.
Do *not* push rules directly to this repository, instead...

The standard rules contributed by the community are found in the `capa-rules` repository.
When you have an idea for a new rule, you should open a PR against `capa-rules`.
We keep `capa` and `capa-rules` separate to distinguish where ideas, bugs, and discussions should happen.
If you're writing yaml it probably goes in `capa-rules` and if you're writing Python it probably goes in `capa`.
Also, we encourage users to develop their own rule repositories, so we treat our default set of rules in the same way.

Test fixtures, such as malware samples and analysis workspaces, are found in the `capa-testfiles` repository.
These are files you'll need in order to run the linter (in `--thorough` mode) and full test suites;
 however, they take up a lot of space (1GB+), so by keeping `capa-testfiles` separate,
 a shallow checkout of `capa` and `capa-rules` doesn't take much bandwidth.

### Design Decisions

When we make a significant decision in how we maintain the project and what we can or cannot support,
 we will document it in the [capa issues tracker](https://github.com/mandiant/capa/issues).
This is the best place review our discussions about what/how/why we do things in the project.
If you have a question, check to see if it is documented there.
If it is *not* documented there, or you can't find an answer, please open a issue.
We'll link to existing issues when appropriate to keep discussions in one place.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for capa.
Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

Before creating bug reports, please check [this list](#before-submitting-a-bug-report)
 as you might find out that you don't need to create one.
When you are creating a bug report, please [include as many details as possible](#how-do-i-submit-a-good-bug-report).
Fill out [the required template](./ISSUE_TEMPLATE/bug_report.md),
 the information it asks for helps us resolve issues faster.

> **Note:** If you find a **Closed** issue that seems like it is the same thing that you're experiencing, open a new issue and include a link to the original issue in the body of your new one.

#### Before Submitting A Bug Report

* **Determine [which repository the problem should be reported in](#capa-and-its-repositories)**.
* **Perform a [cursory search](https://github.com/mandiant/capa/issues?q=is%3Aissue)** to see if the problem has already been reported. If it has **and the issue is still open**, add a comment to the existing issue instead of opening a new one.

#### How Do I Submit A (Good) Bug Report?

Bugs are tracked as [GitHub issues](https://guides.github.com/features/issues/).
After you've determined [which repository](#capa-and-its-repositories) your bug is related to,
 create an issue on that repository and provide the following information by filling in 
 [the template](./ISSUE_TEMPLATE/bug_report.md).

Explain the problem and include additional details to help maintainers reproduce the problem:

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps which reproduce the problem** in as many details as possible. For example, start by explaining how you started capa, e.g. which command exactly you used in the terminal, or how you started capa otherwise.
* **Provide specific examples to demonstrate the steps**. Include links to files or GitHub projects, or copy/pasteable snippets, which you use in those examples. If you're providing snippets in the issue, use [Markdown code blocks](https://help.github.com/articles/markdown-basics/#multiple-lines).
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
* **Explain which behavior you expected to see instead and why.**
* **Include screenshots and animated GIFs** which show you following the described steps and clearly demonstrate the problem. You can use [this tool](https://www.cockos.com/licecap/) to record GIFs on macOS and Windows, and [this tool](https://github.com/colinkeenan/silentcast) or [this tool](https://github.com/GNOME/byzanz) on Linux.
* **If you're reporting that capa crashed**, include the stack trace from the terminal. Include the stack trace in the issue in a [code block](https://help.github.com/articles/markdown-basics/#multiple-lines), a [file attachment](https://help.github.com/articles/file-attachments-on-issues-and-pull-requests/), or put it in a [gist](https://gist.github.com/) and provide link to that gist.
* **If the problem wasn't triggered by a specific action**, describe what you were doing before the problem happened and share more information using the guidelines below.

Provide more context by answering these questions:

* **Did the problem start happening recently** (e.g. after updating to a new version of capa) or was this always a problem?
* If the problem started happening recently, **can you reproduce the problem in an older version of capa?** What's the most recent version in which the problem doesn't happen? You can download older versions of capa from [the releases page](https://github.com/mandiant/capa/releases).
* **Can you reliably reproduce the issue?** If not, provide details about how often the problem happens and under which conditions it normally happens.
* If the problem is related to working with files (e.g. opening and editing files), **does the problem happen for all files and projects or only some?** Does the problem happen only when working with local or remote files (e.g. on network drives), with files of a specific type (e.g. only JavaScript or Python files), with large files or files with very long lines, or with files in a specific encoding? Is there anything else special about the files you are using?

Include details about your configuration and environment:

* **Which version of capa are you using?** You can get the exact version by running `capa --version` in your terminal.
* **What's the name and version of the OS you're using**?

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for capa, including completely new features and minor improvements to existing functionality. Following these guidelines helps maintainers and the community understand your suggestion and find related suggestions.

Before creating enhancement suggestions, please check [this list](#before-submitting-an-enhancement-suggestion) as you might find out that you don't need to create one. When you are creating an enhancement suggestion, please [include as many details as possible](#how-do-i-submit-a-good-enhancement-suggestion). Fill in [the template](./ISSUE_TEMPLATE/feature_request.md), including the steps that you imagine you would take if the feature you're requesting existed.

#### Before Submitting An Enhancement Suggestion

* **Determine [which repository the enhancement should be suggested in](#capa-and-its-repositories).**
* **Perform a [cursory search](https://github.com/mandiant/capa/issues?q=is%3Aissue)** to see if the enhancement has already been suggested. If it has, add a comment to the existing issue instead of opening a new one.

#### How Do I Submit A (Good) Enhancement Suggestion?

Enhancement suggestions are tracked as [GitHub issues](https://guides.github.com/features/issues/). After you've determined [which repository](#capa-and-its-repositories) your enhancement suggestion is related to, create an issue on that repository and provide the following information:

* **Use a clear and descriptive title** for the issue to identify the suggestion.
* **Provide a step-by-step description of the suggested enhancement** in as many details as possible.
* **Provide specific examples to demonstrate the steps**. Include copy/pasteable snippets which you use in those examples, as [Markdown code blocks](https://help.github.com/articles/markdown-basics/#multiple-lines).
* **Describe the current behavior** and **explain which behavior you expected to see instead** and why.
* **Include screenshots and animated GIFs** which help you demonstrate the steps or point out the part of capa which the suggestion is related to. You can use [this tool](https://www.cockos.com/licecap/) to record GIFs on macOS and Windows, and [this tool](https://github.com/colinkeenan/silentcast) or [this tool](https://github.com/GNOME/byzanz) on Linux.
* **Explain why this enhancement would be useful** to most capa users and isn't something that can or should be implemented as an external tool that uses capa as a library.
* **Specify which version of capa you're using.** You can get the exact version by running `capa --version` in your terminal.
* **Specify the name and version of the OS you're using.**

### Your First Code Contribution

Unsure where to begin contributing to capa? You can start by looking through these `good-first-issue` and `rule-idea` issues:

* [good-first-issue](https://github.com/mandiant/capa/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) - issues which should only require a few lines of code, and a test or two.
* [rule-idea](https://github.com/mandiant/capa-rules/issues?q=is%3Aissue+is%3Aopen+label%3A%22rule+idea%22) - issues that describe potential new rule ideas.

Both issue lists are sorted by total number of comments. While not perfect, number of comments is a reasonable proxy for impact a given change will have.

#### Local development

capa and all its resources can be developed locally. 
For instructions on how to do this, see the "Method 3" section of the [installation guide](https://github.com/mandiant/capa/blob/master/doc/installation.md).

### Pull Requests

The process described here has several goals:

- Maintain capa's quality
- Fix problems that are important to users
- Engage the community in working toward the best possible capa
- Enable a sustainable system for capa's maintainers to review contributions

Please follow these steps to have your contribution considered by the maintainers:

1. Follow the [styleguides](#styleguides)
2. Update the CHANGELOG and add tests and documentation. In case they are not needed, indicate it in [the PR template](pull_request_template.md).
3. After you submit your pull request, verify that all [status checks](https://help.github.com/articles/about-status-checks/) are passing <details><summary>What if the status checks are failing? </summary>If a status check is failing, and you believe that the failure is unrelated to your change, please leave a comment on the pull request explaining why you believe the failure is unrelated. A maintainer will re-run the status check for you. If we conclude that the failure was a false positive, then we will open an issue to track that problem with our status check suite.</details>

While the prerequisites above must be satisfied prior to having your pull request reviewed, the reviewer(s) may ask you to complete additional design work, tests, or other changes before your pull request can be ultimately accepted.

## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Prefix the first line with the component in question ("rules: ..." or "render: ...")
* Reference issues and pull requests liberally after the first line

### Python Styleguide

All Python code must adhere to the style guide used by capa: 

  1. [PEP8](https://www.python.org/dev/peps/pep-0008/), with clarifications from
  2. [Willi's style guide](https://docs.google.com/document/d/1iRpeg-w4DtibwytUyC_dDT7IGhNGBP25-nQfuBa-Fyk/edit?usp=sharing), formatted with
  3. [isort](https://pypi.org/project/isort/) (with line width 120 and ordered by line length), and formatted with
  4. [black](https://github.com/psf/black) (with line width 120), and formatted with
  5. [dos2unix](https://linux.die.net/man/1/dos2unix)
  
Our CI pipeline will reformat and enforce the Python styleguide.
 
### Rules Styleguide

All (non-nursery) capa rules must:

  1. pass the [linter](https://github.com/mandiant/capa/blob/master/scripts/lint.py), and
  2. be formatted with [capafmt](https://github.com/mandiant/capa/blob/master/scripts/capafmt.py)
  
This ensures that all rules meet the same minimum level of quality and are structured in a consistent way.
Our CI pipeline will reformat and enforce the capa rules styleguide.
