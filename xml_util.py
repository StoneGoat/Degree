
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

def sanitize_tag(tag):
    tag = str(tag)
    if tag and tag[0].isdigit():
        tag = "tag_" + tag
    tag = tag.replace(".", "_").replace(" ", "_")
    return tag

def dict_to_xml(tag, d):
    elem = ET.Element(sanitize_tag(tag))
    for key, val in d.items():
        key_str = sanitize_tag(key)
        if isinstance(val, dict):
            child = dict_to_xml(key_str, val)
            elem.append(child)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    child = dict_to_xml(key_str, item)
                else:
                    child = ET.Element(key_str)
                    child.text = str(item)
                elem.append(child)
        else:
            child = ET.Element(key_str)
            child.text = str(val)
            elem.append(child)
    return elem

def convert_dict_to_pretty_xml(root_tag, d):
    root = dict_to_xml(root_tag, d)
    xml_str = ET.tostring(root, encoding="unicode", method="xml")
    dom = minidom.parseString(xml_str)
    return dom.toprettyxml(indent="    ")
