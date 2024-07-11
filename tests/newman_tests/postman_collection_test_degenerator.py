import json
import os

import yaml
from src.input_models import TestSuite as InputTestSuite
from src.mappings import map_domain_out_in
from src.output_models import TestSuite as OutputTestSuite
from src.yaml_dumper import dump_yaml


def do_the_thing(intput_file_name: str, output_file_name: str, testing: bool = False):
    with open(intput_file_name) as file:
        complexified_tests = json.load(file)

    validated_tests = OutputTestSuite(**complexified_tests)

    full_tests = InputTestSuite(info=validated_tests.info, variable=validated_tests.variable, item=[])
    for item in validated_tests.item:
        full_tests.item.append(map_domain_out_in(item))

    if testing:
        with open(output_file_name, "w") as file:
            file.write(dump_yaml(full_tests.model_dump(exclude_none=True)))
    else:
        with open(output_file_name, "w") as file:
            file.write(yaml.dump(full_tests.model_dump(exclude_none=True), default_flow_style=False, indent=4))


if __name__ == "__main__":
    path = os.path.dirname(os.path.realpath(__file__))
    do_the_thing(
        f"{path}/RESC_web_service.postman_collection.json", f"{path}/RESC_web_service.postman_collection.yaml", True
    )
