import re

from src.input_models import Domain as InputDomain
from src.input_models import EndPoint as InputEndPoint
from src.input_models import Query as InputQuery
from src.output_models import (
    Body,
    Event,
    FormType,
    QueryString,
    Request,
    Script,
    Url,
)
from src.output_models import Domain as OutputDomain
from src.output_models import EndPoint as OutputEndpoint
from src.output_models import Query as OutputQuery


# Mapping Query
def map_query_in_out(input_query: InputQuery) -> OutputQuery:
    print(f"\t\t{input_query.name}")
    test_response_time = time_to_test_response_time(input_query.response_time)
    actual_tests = tests_to_test_script(input_query.tests)
    test_response_code = code_to_test_response_code(input_query.status_code)

    exec_script = []
    exec_script.extend(test_response_code)
    exec_script.extend(actual_tests)
    exec_script.extend(test_response_time)
    events = [
        Event(
            script=Script(exec=exec_script)  ## Split the test here.
        )
    ]

    if input_query.prerequest:
        events.append(
            Event(
                listen="prerequest",
                script=Script(exec=input_query.prerequest.split("\n")),
            )
        )

    header = [QueryString.of_dict(input_query.header)] if input_query.header else []
    body = None
    if input_query.form_raw:
        body = Body(mode=FormType.raw, raw=input_query.form_raw)
        if len(header) == 0:
            header.append(QueryString(key="Content-Type", value="application/json"))
        else:
            if header[0].key != "Content-Type":
                header.append(QueryString(key="Content-Type", value="application/json"))
    elif input_query.form_data:
        body = Body(mode=FormType.formdata, formdata=input_query.form_data)

    path_query = input_query.request.split("?")
    queries: list[QueryString] | None = None
    if len(path_query) > 1:
        query_strings = path_query[1].split("&")
        queries = [QueryString.of_str(query_string) for query_string in query_strings]
    path = path_query[0].split("/")

    variables: list[QueryString] | None = (
        [QueryString.of_dict(variable) for variable in input_query.variables] if input_query.variables else None
    )

    request = Request(
        method=input_query.method,
        header=header,
        body=body,
        url=Url(
            host=["{{baseUrl}}"],
            path=path,
            query=queries,
            variable=variables,
        ),
    )

    return OutputQuery(
        name=input_query.name,
        event=events,
        request=request,
    )


def map_query_out_in(output_query: OutputQuery) -> InputQuery:
    print(f"\t\t{output_query.name}")
    request: Request = output_query.request

    # get script
    test_script: list[str] | None = None
    prerequest_script: list[str] | None = None
    for event in output_query.event:
        if event.listen == "test":
            test_script = event.script.exec
            test_script = test_script[5:-4]
        if event.listen == "prerequest" and event.script.exec != [""]:
            prerequest_script = event.script.exec

    form = output_query.request.body
    formdata = None
    formraw = None
    if form and form.formdata:
        formdata = form.formdata
    if form and form.raw:
        formraw = form.raw

    num = re.compile("([0-9]{3,5})")
    status_code: re.Match | None = num.search(output_query.event[0].script.exec[0])
    if not status_code:
        raise RuntimeError("status code not found")

    response_time: re.Match | None = num.search(output_query.event[0].script.exec[-2])
    if not response_time:
        raise RuntimeError("response_time not found")

    path = "/".join(request.url.path)
    if request.url.query:
        path = path + "?" + "&".join([query.to_str() for query in request.url.query])

    header: str | None = None
    if request.header:
        if formraw and request.header[0].key == 'Content-Type':
            header = None
        else:
            header = request.header[0].to_dict()

    return InputQuery(
        name=output_query.name,
        method=request.method,
        header=header,
        request=path,
        variables=[variable.to_dict() for variable in request.url.variable] if request.url.variable else None,
        status_code=status_code.group(),
        response_time=response_time.group(),
        tests="\n".join(test_script) if test_script else None,
        prerequest="\n".join(prerequest_script) if prerequest_script else None,
        form_data=formdata,
        form_raw=formraw,
    )


# Mapping End points
def map_end_point_in_out(input_endpoint: InputEndPoint) -> OutputEndpoint:
    print(f"\t{input_endpoint.name}")
    return OutputEndpoint(
        name=input_endpoint.name,
        item=[map_query_in_out(query) for query in input_endpoint.item],
    )


def map_end_point_out_in(output_endpoint: OutputDomain) -> InputEndPoint:
    print(f"\t{output_endpoint.name}")
    return InputEndPoint(name=output_endpoint.name, item=[map_query_out_in(query) for query in output_endpoint.item])


# Mapping Domains
def map_domain_in_out(input_domain: InputDomain) -> OutputDomain:
    print(input_domain.name)
    return OutputDomain(
        name=input_domain.name,
        item=[map_end_point_in_out(endpoint) for endpoint in input_domain.item],
    )


def map_domain_out_in(output_domain: OutputDomain) -> InputDomain:
    print(output_domain.name)
    return InputDomain(
        name=output_domain.name, item=[map_end_point_out_in(endpoint) for endpoint in output_domain.item]
    )


# get test reponse
def time_to_test_response_time(expect_response_time: int) -> list[str]:
    return [
        "",
        f'pm.test("Response time is less than {expect_response_time}ms", function () {{',
        f"    pm.expect(pm.response.responseTime).to.be.below({expect_response_time});",
        "});",
    ]


def tests_to_test_script(tests: str | None) -> list[str]:
    if not tests:
        return []
    tests_array = [
        "const responseJson = pm.response.json();",
    ]
    tests_array.extend(tests.split("\n"))
    return tests_array


def code_to_test_response_code(expected_code: int) -> list[str]:
    return [
        f'pm.test("Status code is {expected_code}", function () {{',
        f"    pm.response.to.have.status({expected_code});",
        "});",
        "",
    ]
