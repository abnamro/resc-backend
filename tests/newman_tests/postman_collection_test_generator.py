import json
import os

import yaml
from src.input_models import TestSuite as InputTestSuite
from src.mappings import map_domain_in_out
from src.output_models import TestSuite as OutputTestSuite


def do_the_thing(intput_file_name: str, output_file_name: str):
    with open(intput_file_name) as file:
        simplified_tests = yaml.safe_load(file)

    # print(simplified_tests)
    validated_tests = InputTestSuite(**simplified_tests)

    full_tests = OutputTestSuite(info=validated_tests.info, variable=validated_tests.variable, item=[])
    for item in validated_tests.item:
        full_tests.item.append(map_domain_in_out(item))

    with open(output_file_name, "w") as file:
        file.write(json.dumps(full_tests.model_dump(exclude_none=True), indent="\t"))


if __name__ == "__main__":
    path = os.path.dirname(os.path.realpath(__file__))
    do_the_thing(f"{path}/RESC_web_service.postman_collection.yaml", f"{path}/RESC_web_service.postman_collection.json")
