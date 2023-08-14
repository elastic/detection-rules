"""
Generates an investigation guide for a given rule-uuid.
Requires OPENAI_API_KEY in a .env file in the root
of the project.

From the root of the Github repository, activate the
poetry venv and run the CLI:
> poetry shell
> python -m detection_rules guide gen-investigation-guide --rule-id b25a7df2-120a-4db2-bd3f-3e4b86b24bee
"""

import os
import textwrap
import time

import click
import openai
from dotenv import find_dotenv, load_dotenv
from loguru import logger

from detection_rules.rule_loader import RuleCollection

# Constants
MODEL = "gpt-4-32k"
DEPLOYMENT_ID = "protections-gpt3-32k"
TEMPERATURE = 0  # degree of randomness of the model's output
SLEEP_TIME = 30  # to avoid hitting rate limits

# Configure OpenAI API
load_dotenv(find_dotenv())  # read local .env file
openai.api_key  = os.getenv('OPENAI_API_KEY')
openai.api_type = "azure"
openai.api_base = "https://security-protections.openai.azure.com/"
openai.api_version = "2023-05-15"

if openai.api_key is None:
    raise ValueError("OPENAI_API_KEY not provided!")

# Import after dotenv configurations
from detection_rules.main import root

def get_completion(prompt):
    """
    Get the chat completion based on the provided prompt.
    """
    logger.debug(f"Generating completion for prompt={prompt}")
    messages = [{"role": "user", "content": prompt}]
    response = openai.ChatCompletion.create(
        model=MODEL,
        deployment_id=DEPLOYMENT_ID,
        messages=messages,
        temperature=TEMPERATURE,
    )
    return response.choices[0].message["content"]


def get_fp_examples():
    """Get the false positive examples from the guide library."""
    fp_examples = textwrap.dedent("""

    ```
    - This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.
    ```

    ```
    - This activity is unlikely to happen legitimately. Any activity that triggered the alert and is not inherently malicious must be monitored by the security team.
    ```

    ```
    - This activity should not happen legitimately. The security team should address any potential benign true positive (B-TP), as this configuration can put the user and the domain at risk.
    ```

    ```
    - This mechanism can be used legitimately. Analysts can dismiss the alert if the administrator is aware of the activity and there are justifications for {MODIFY_ME}.
    ```

    ```
    - If this activity is expected and noisy in your environment, consider adding exceptions — preferably with a combination of {MODIFY_ME} and {MODIFY_ME} conditions.
    ```

    ```
    - Examine the history of the command. If the command only manifested recently, it might be part of a new automation module or script. If it has a consistent cadence (for example, it appears in small numbers on a weekly or monthly cadence), it might be part of a housekeeping or maintenance process.
    ```

    ```
    - Try to understand the context of the execution by thinking about the user, machine, or business purpose. A small number of endpoints, such as servers with unique software, might appear unusual but satisfy a specific business need.
    ```

    ```
    - If this activity is related to new benign software installation activity, consider adding exceptions — preferably with a combination of user and command line conditions.
    ```

    ```
    - Regular users should not need {MODIFY_ME}, which makes false positives unlikely. In the case of authorized benign true positives (B-TPs), exceptions can be added.
    ```

    ```
    - This rule has a high chance to produce false positives because it detects communication with legitimate services. Noisy false positives can be added as exceptions.
    ```

    ```
    This rule alerts the intended usage of the service that can be abused and compromise the environment. Tuning is needed to have higher confidence. Consider adding exceptions — preferably with a combination of the user agent and IP address conditions.
    ```

    #### Azure AD

    ```
    - Administrators may use custom accounts on Azure AD Connect, investigate if it is the case, and if it is properly secured. If noisy in your environment due to expected activity, consider adding the corresponding account as an exception.
    ```

    #### Discovery

    ```
    - Discovery activities are not inherently malicious if they occur in isolation. As long as the analyst did not identify suspicious activity related to the user or host, such alerts can be dismissed.
    ```

    #### Log Clear

    ```
    - Administrators may rotate these logs after a certain period as part of their retention policy or after importing them to a SIEM.
    ```

    #### Compression

    ```
    - Backup software can use these utilities. Check the `process.parent.executable` and `process.parent.command_line` fields to determine what triggered the encryption.
    ```

    #### Dual-Use

    ```
    - This is a dual-use tool, meaning its usage is not inherently malicious. Analysts can dismiss the alert if the administrator is aware of the activity, no other suspicious activity was identified, and there are justifications for the execution.
    ```


    ```
    - {MODIFY_ME} is a dual-use tool that can be used for benign or malicious activity. It is included in some Linux distributions, so its presence is not necessarily suspicious. Some normal use of this program, while uncommon, may originate from scripts, automation tools, and frameworks.
    ```
    """).lstrip()
    return fp_examples


def get_rules(rule_context, rules_100):
    """
    Get the response with the rules based on the provided rule context.
    """
    chunk_prompt = textwrap.dedent(f"""
    "Based on the information provided in the {rule_context} provide useful related rule list of Elastic detection rules that monitor for similar or connected activities to the <Rule Name> rule. Limit the number of related rules to the top 5. If none of the provided detection rules match the <Rule Name> then don't identify any related rules.

    Here are some examples of current Elastic detection rules to populate this section:

    {rules_100}

    Format the rules as markdown bulleted list as <Rule Name> - <Rule UUID>.
    """).lstrip()
    response = get_completion(chunk_prompt)
    time.sleep(SLEEP_TIME)
    return response


def get_section(section: str, rule_context: str, prior_context: str = "", prompt_choice: str = "a"):
    """
    Generates a section of the investigation guide based on the provided context.

    :param section: Name of the section to generate.
    :param rule_context: Rule context to be used for generation.
    :param prior_context: Prior section content to consider in the generation.
    :param prompt_choice: Key to select the specific prompt for a section.
    :return: Generated section content.
    """
    # Prompts for each section
    prompts = {
        "investigating_rule_name": {
            "d": textwrap.dedent(f"""
            Imagine you are an expert security detection engineer writing a section titled 'Investigating <Rule Name>' for a security analyst. Given the detection rule content provided:

            ```
            {rule_context}
            ```

            In this section, provide a brief explanation about the role and functioning of the underlying technology related to the <Rule Name> in their respective environments. Describe how adversaries might abuse this technology for malicious purposes. Finally, elucidate how the detection rule '<Rule Name>' is designed to detect such abuse based on its rule content. Do not copy verbatim from the detection rule content in the output, but you may use the information to guide your explanation. The section is roughly 300-400 characters. Format the output as follows:

            ### Investigating <Rule Name>
            <Generated content>
            """).lstrip()
        },
        "investigative_steps": {
            "b": textwrap.dedent(f"""
            "Based on the previous information provided: \n\n```\n{prior_context}\n``` and \n```\n{rule_context}\n```\n Conceive a section titled 'Possible investigation steps'. This section should propose a detailed series of bulleted tasks an analyst might take to triage, gather context, and investigate an alert triggered by the <Rule Name> rule. If recommending using Osquery as part of the investigation method, provide an example specific to the <Rule Name>. Limit the number of steps to 10. Format the output as follows with a bulleted list of tasks without using numbered bullets:

            #### Possible investigation steps

            <Generated bulleted tasks for investigation>
            """).lstrip()
        },
        "false_positive_analysis": {
            "c": textwrap.dedent(f"""
            "Based on the previous information provided: \n\n```\n{prior_context}\n``` and \n```\n{rule_context}\n```\n Compose a section titled 'False positive analysis'. In this section, describe known false positives associated with the <Rule Name> rule and how customers can manage these by excluding noisy behaviors, using workflows like exceptions. Limit the number of steps to 5.

            Here are some examples of false positive analysis that may help format the tasks in this section:

            {get_fp_examples()}

            Format the output as follows with a bulleted list of tasks without using numbered bullets:

            #### False positive analysis

            <Generated content describing known false positives and ways to manage them>"
            """).lstrip(),
            "d": textwrap.dedent(f"""
            "Based on the previous information provided: \n\n```\n{prior_context}\n```\n\nCompose a section titled 'False positive analysis'. In this section, describe the specific false positives associated with the query. Limit the number of FPs to under 10. If there are no known false positives, state that there are no known false positives. Format the output as follows with a bulleted list of tasks without using numbered bullets:

            #### False positive analysis

            <Generated content describing known false positives and ways to manage them>"
            """).lstrip()
        },
        "related_rules": {
            "c": textwrap.dedent(f"""
            "Based on the previous information provided: \n\n```\n{prior_context}\n``` and \n```\n{rule_context}\n```\n Conceive a section titled 'Related Rules'. In this section, provide useful related rule references such as Elastic detection rules that monitor for similar or connected activities to the <Rule Name> rule. Format the rules as markdown bulleted list as <Rule Name> - <Rule UUID>. Format the output as follows:

            #### Related Rules

            <Generated related rules in markdown format>"
            """).lstrip()
        },
        "response_and_remediation": {
            "a": textwrap.dedent(f"""
            "Based on the previous information provided: \n\n```\n{prior_context}\n``` and \n```\n{rule_context}\n```\n Develop a section titled 'Response and remediation'. This section should suggest actions to contain, remediate, and escalate an alert based on the triage results. It should also provide guidance on enhancing future investigations, such as implementing logging policies and additional integrations. Outline steps to restore the system to its operational state and suggest hardening measures. Format the output as follows with a bulleted list of tasks without using numbered bullets:

            Response and remediation

            <Generated content outlining response and remediation steps>"
            """).lstrip()
        }
    }

    # Get the specific prompt for the section
    prompt = prompts[section][prompt_choice]

    # Generate section content
    return get_completion(prompt)


def get_related_rules_section(rule_context, prior_context, rules):
    """
    Get the related rules section based on the rule context and prior context.
    """
    rule_name_uuids = [f"{rule.name} - {rule.id}" for rule in rules.rules]
    chunks = [rule_name_uuids[x:x+100] for x in range(0, len(rule_name_uuids), 100)]
    identified_rules = [get_rules(rule_context, "\n".join(chunk)) for chunk in chunks]
    merge_chunks = "\n".join(identified_rules)

    # Define the prompt
    prompt = textwrap.dedent(f"""
        "Based on the previous information provided: \n\n```\n{prior_context}\n``` and \n```\n{rule_context}\n```\n Conceive a section titled 'Related Rules'. In this section, provide useful related rule references such as Elastic detection rules that monitor for similar or connected activities to the <Rule Name> rule. Limit the number of related rules to the top 5.

        Here are some examples of current Elastic detection rules to populate this section:

        {merge_chunks}

        Format the rules as markdown bulleted list as <Rule Name> - <Rule UUID>. Format the output as follows:

        #### Related Rules

        <Generated related rules in markdown format>"
    """).lstrip()
    # Get the completion
    return get_completion(prompt)


def get_guide(rule_context, rules):
    """
    Generate the investigation guide based on the rule context.
    """
    investigating_rule_name = get_section(section="investigating_rule_name", prompt_choice='d', rule_context=rule_context)
    investigative_steps = get_section(section="investigative_steps", prompt_choice='b', rule_context=rule_context, prior_context=investigating_rule_name)
    false_positive_analysis = get_section(section="false_positive_analysis", prompt_choice='c', rule_context=rule_context, prior_context=investigating_rule_name)
    # related_rules = get_related_rules_section(rule_context, investigating_rule_name, rules)  # more accurate but expensive
    related_rules = get_section(section="related_rules", prompt_choice='c', rule_context=rule_context, prior_context=investigating_rule_name)
    response_and_remediation = get_section(section="response_and_remediation", prompt_choice='a', rule_context=rule_context, prior_context=investigating_rule_name)

    guide = textwrap.dedent(f"""## Triage and analysis\n
    {investigating_rule_name}\n
    {investigative_steps}\n
    {false_positive_analysis}\n
    {related_rules}\n
    {response_and_remediation}
    """).lstrip()

    return guide


def get_rule_context(rule):
    """
    Get the rule context for the given rule.
    """
    rule_name = rule.name
    rule_description = rule.contents.data.description
    rule_query = rule.contents.data.query

    rule_context = textwrap.dedent(f"""
    Name
    {rule_name}

    Description
    {rule_description}

    Query
    {rule_query}
    """).lstrip()

    return rule_context


@root.group('guide')
def guide_group():
    """Commands related to the Elastic Stack rules release lifecycle."""


@guide_group.command()
@click.option('--rule-id', help='The rule ID')
def gen_investigation_guide(rule_id):
    """
    Generate the investigation guide for the given rule ID.
    """
    # Load rule by ID
    rules = RuleCollection.default()
    rule = [r for r in rules.rules if r.id == rule_id][0]

    # Get the rule context
    rule_context = get_rule_context(rule)

    # Generate the investigation guide
    rule_guide = get_guide(rule_context, rules)
    print(rule_guide)
