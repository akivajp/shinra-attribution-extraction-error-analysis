#!/usr/bin/env python3.8

import argparse
import json
import sys
import traceback
from typing import Dict, List, Set, Tuple, Any, Optional

import csv
import os
from logzero import logger
from tqdm import tqdm
#from bs4 import BeautifulSoup

SHORT_DEBUG_COUNT = 1000
#SHORT_DEBUG_COUNT = 10000
SHORT_DEBUG = False
#SHORT_DEBUG = True

all_html_dir = None

def load_json(path: str) -> List[Dict]:
    #print(path, file=sys.stderr)
    logger.debug('load json: %s', path)
    with open(path, "r", encoding="utf-8-sig") as f:
        #return [json.loads(line) for line in f.readlines()]
        lines = f.readlines()
        records = []
        for i, line in enumerate(tqdm(lines)):
            if SHORT_DEBUG and i > SHORT_DEBUG_COUNT:
                break
            rec = json.loads(line)
            if all_html_dir:
                rec = check_in_tags(all_html_dir, rec)
            #if rec.get('html_offset'):
            #    rec['attribute_value'] = rec['html_offset']['text']
            #else:
            #    rec['attribute_value'] = rec['text_offset']['text']
            records.append(rec)
        return records

def check_in_tags(html_dir, rec):
    text = open(html_dir + '/' + rec['page_id'] + '.html').read()
    lines = text.splitlines()
    #soup = BeautifulSoup(text, 'html.parser')
    #logger.debug(soup)
    #results.setdefault('train_samples_in_table', 0)
    html_offset = rec['html_offset']
    start_line = html_offset['start']['line_id']
    start_offset = html_offset['start']['offset']
    end_line = html_offset['end']['line_id']
    end_offset = html_offset['end']['offset']
    #logger.debug(lines[start_line][start_offset:end_offset])
    substr1 = str.join('', lines[0:start_line] + [lines[start_line][0:start_offset]]).lower()
    #substr2 = str.join('', [lines[end_line][end_offset:]] + lines[end_line+1:]).lower()
    def check_in_tag(tag, keyword=None):
        #end_table_tag = substr2.find(f'</{tag}>')
        #if end_table_tag < 0:
        #    return False
        #if substr2[:end_table_tag].find(f'<{tag}') >= 0:
        #    return True
        start_tag = substr1.rfind(f'<{tag}')
        if start_tag < 0:
            return False
        end_tag = substr1.find(f'</{tag}>', start_tag)
        if end_tag >= 0:
            # 属性値の前で閉じタグがある
            return False
        if keyword:
            #tag = substr1[start_tag:end_tag+len(tag)+2]
            #logger.debug(start_tag)
            #logger.debug(end_tag)
            #logger.debug(tag)
            #if tag.find(keyword) >= 0:
            if substr1.find(keyword, start_tag) >= 0:
                return True
            else:
                return False
        return True
    rec['in_table'] = check_in_tag('table')
    #rec['in_list'] = check_in_tag('ul')
    rec['in_list'] = check_in_tag('ul') or check_in_tag('ol') or check_in_tag('dl')
    rec['in_infobox'] = check_in_tag('table', 'infobox')
    rec['in_body'] = not rec['in_table'] and not rec['in_list']
    return rec

def make_hashes(json_text: Dict[str, Any]) -> Tuple[Optional[int], Optional[int], str]:
    text_hash: Optional[int] = None
    html_hash: Optional[int] = None
    if json_text.get("text_offset") is not None:
        text_hash = hash((
            str(json_text["page_id"]),
            str(json_text["ENE"]),
            str(json_text["attribute"]),
            str(json_text["text_offset"]["start"]["line_id"]),
            str(json_text["text_offset"]["start"]["offset"]),
            str(json_text["text_offset"]["end"]["line_id"]),
            str(json_text["text_offset"]["end"]["offset"]),
        ))
    if json_text.get("html_offset") is not None:
        html_hash = hash((
            str(json_text["page_id"]),
            str(json_text["ENE"]),
            str(json_text["attribute"]),
            str(json_text["html_offset"]["start"]["line_id"]),
            str(json_text["html_offset"]["start"]["offset"]),
            str(json_text["html_offset"]["end"]["line_id"]),
            str(json_text["html_offset"]["end"]["offset"]),
        ))
    #logger.info('json_text: %s', json_text)
    #return text_hash, html_hash, str(json_text["ENE"])
    return text_hash, html_hash, str(json_text["ENE"]), str(json_text["attribute"])

def make_hashes_nopos(json_text: Dict[str, Any]) -> Tuple[Optional[int], Optional[int], str]:
    text_hash: Optional[int] = None
    html_hash: Optional[int] = None
    if json_text.get("text_offset") is not None:
        text_hash = hash((
            str(json_text["page_id"]),
            str(json_text["ENE"]),
            str(json_text["attribute"]),
            #str(json_text["text_offset"]["start"]["line_id"]),
            #str(json_text["text_offset"]["start"]["offset"]),
            #str(json_text["text_offset"]["end"]["line_id"]),
            #str(json_text["text_offset"]["end"]["offset"]),
            str(json_text["text_offset"]["text"]),
        ))
    if json_text.get("html_offset") is not None:
        html_hash = hash((
            str(json_text["page_id"]),
            str(json_text["ENE"]),
            str(json_text["attribute"]),
            #str(json_text["html_offset"]["start"]["line_id"]),
            #str(json_text["html_offset"]["start"]["offset"]),
            #str(json_text["html_offset"]["end"]["line_id"]),
            #str(json_text["html_offset"]["end"]["offset"]),
            str(json_text["html_offset"]["text"]),
        ))
    #logger.info('json_text: %s', json_text)
    #return text_hash, html_hash, str(json_text["ENE"])
    return text_hash, html_hash, str(json_text["ENE"]), str(json_text["attribute"])


def evaluate(submission_path: str, answer_path: str) -> Dict[str, Dict[str, float]]:
#def evaluate(submission_path: str, answer_path: str, html_dir) -> Dict[str, Dict[str, float]]:
    #def get_initial_results() -> Dict[str, Dict[str, float]]:
    def get_initial_results() -> Dict[Any, Dict[str, float]]:
        return {
            "all": {
                "answer_total": 0,
                "submission_total": 0,
                "valid_submission_num": 0,
                "correct_num": 0,
                'answers_in_table': 0,
                'answers_in_list': 0,
                'answers_in_infobox': 0,
                'answers_in_body': 0,
                'correct_in_table': 0,
                'correct_in_list': 0,
                'correct_in_infobox': 0,
                'correct_in_body': 0,
                'submissions_in_table': 0,
                'submissions_in_list': 0,
                'submissions_in_infobox': 0,
                'submissions_in_body': 0,
                'answers_total_nopos': 0,
                'submission_total_nopos': 0,
                "valid_submission_num_nopos": 0,
                'correct_num_nopos': 0,
            },
            "macro": {
                "precision": 0,
                "recall": 0,
                "F-measure": 0,
                'f_in_table': 0,
                'f_in_list': 0,
                'f_in_infobox': 0,
                'f_in_body': 0,
            },
            "micro": {
                "precision": 0,
                "recall": 0,
                "F-measure": 0,
            },
        }
    #results: Dict[str, Dict[str, float]] = {
    results1: Dict[str, Dict[str, float]] = get_initial_results()
    results2 = get_initial_results()
    submission_list: List[Dict] = load_json(submission_path)
    answer_list: List[Dict] = load_json(answer_path)

    answer_page_ids = set([answer["page_id"] for answer in answer_list])
    submission_list = [submission for submission in submission_list if submission["page_id"] in answer_page_ids]

    #submissions: Dict[int, Tuple[Optional[int], Optional[int], str]] = {}
    #answers: Dict[int, Tuple[Optional[int], Optional[int], str]] = {}
    submissions: Dict[int, Tuple[Optional[int], Optional[int], str, str]] = {}
    answers: Dict[int, Tuple[Optional[int], Optional[int], str, str]] = {}
    answers_info = {}
    submissions_info = {}

    submissions_nopos: Dict[int, Tuple[Optional[int], Optional[int], str, str]] = {}
    answers_nopos: Dict[int, Tuple[Optional[int], Optional[int], str, str]] = {}
    answers_info_nopos = {}
    submissions_info_nopos = {}

    categories: Set[str] = set()
    #attributes: Set[str] = set()
    #category_attributes: Set[str] = set()
    categories_in_table: Set[str] = set()
    categories_in_infobox: Set[str] = set()
    categories_in_list: Set[str] = set()
    categories_in_body: Set[str] = set()
    #attributes_in_table: Set[str] = set()
    #attributes_in_infobox: Set[str] = set()
    #attributes_in_list: Set[str] = set()
    #attributes_in_body: Set[str] = set()
    category_attribute_pairs = set()
    category_attribute_pairs_in_table: Set[str] = set()
    category_attribute_pairs_in_infobox: Set[str] = set()
    category_attribute_pairs_in_list: Set[str] = set()
    category_attribute_pairs_in_body: Set[str] = set()

    for submission in submission_list:
        hashes = make_hashes(submission)
        key = hash(hashes)
        if submissions.get(key) is None:
            submissions[key] = hashes
            submissions_info[key] = submission
        # nopos
        hashes = make_hashes_nopos(submission)
        key = hash(hashes)
        if submissions_nopos.get(key) is None:
            submissions_nopos[key] = hashes

    #def process_answers(results):
    def process_answers():
        for answer in answer_list:
            hashes = make_hashes(answer)
            hashes_nopos = make_hashes_nopos(answer)
            category = hashes[2]
            attribute = hashes[3]
            categories.add(category)
            #attributes.add(attribute)
            #category_attributes.add( (category,attribute) )
            category_attribute_pairs.add((category, attribute))

            if answer.get('in_table'):
                categories_in_table.add(category)
                #attributes_in_table.add(attribute)
                category_attribute_pairs_in_table.add( (category,attribute) )
            if answer.get('in_infobox'):
                categories_in_infobox.add(category)
                #attributes_in_infobox.add(attribute)
                category_attribute_pairs_in_infobox.add( (category,attribute) )
            if answer.get('in_list'):
                categories_in_list.add(category)
                #attributes_in_list.add(attribute)
                category_attribute_pairs_in_list.add( (category,attribute) )
            if answer.get('in_body'):
                categories_in_body.add(category)
                #attributes_in_body.add(attribute)
                category_attribute_pairs_in_body.add( (category,attribute) )

            def add_entry(results, result_key):
                #if results.get(category) is None:
                if results.get(result_key) is None:
                    #results[category] = {
                    results[result_key] = {
                        "answer_total": 1,
                        "submission_total": 0,
                        "valid_submission_num": 0,
                        "correct_num": 0,
                        "answer_total_nopos": 1,
                        "submission_total_nopos": 0,
                        "valid_submission_num_nopos": 0,
                        "correct_num_nopos": 0,
                        #"submission_in_table": 0,
                        #"submission_in_list": 0,
                        #"submission_in_infobox": 0,
                        #"submission_in_box": 0,
                    }
                    #results[result_key]['answers_in_table'] = 0
                    #results[result_key]['answers_in_list'] = 0
                    #results[result_key]['answers_in_infobox'] = 0
                    #results[result_key]['answers_in_body'] = 0
                    #results[result_key]['correct_in_table'] = 0
                    #results[result_key]['correct_in_list'] = 0
                    #results[result_key]['correct_in_infobox'] = 0
                    #results[result_key]['correct_in_body'] = 0
                    for in_tag in ['in_table', 'in_list', 'in_infobox', 'in_body']:
                        results[result_key]['answers_' + in_tag] = 0
                        results[result_key]['correct_' + in_tag] = 0
                        results[result_key]['submissions_' + in_tag] = 0
                else:
                    #results[category]["answer_total"] += 1
                    results[result_key]["answer_total"] += 1
                    #if html_dir:
                    #    results[result_key]['answers_in_table'] += info['in_table']
                    #    results[result_key]['answers_in_list'] += info['in_list']
                    #    results[result_key]['answers_in_infobox'] += info['in_infobox']
                results["all"]["answer_total"] += 1
                #if answer.get('in_table'):
                #    results[result_key]['answers_in_table'] += 1
                #    results['all']['answers_in_table'] += 1
                #if answer.get('in_list'):
                #    results[result_key]['answers_in_list'] += 1
                #    results['all']['answers_in_list'] += 1
                #if answer.get('in_infobox'):
                #    results[result_key]['answers_in_infobox'] += 1
                #    results['all']['answers_in_infobox'] += 1
                #if answer.get('in_body'):
                #    results[result_key]['answers_in_body'] += 1
                #    results['all']['answers_in_body'] += 1
                for in_tag in ['in_table', 'in_list', 'in_infobox', 'in_body']:
                    if answer.get(in_tag):
                        results[result_key]['answers_' + in_tag] += 1
                        results['all']['answers_' + in_tag] += 1
                page_ids = results[result_key].setdefault('page_ids', set())
                page_ids.add(answer['page_id'])
                results[result_key]['test_pages'] = len(page_ids)
                #all_page_ids = results['all'].setdefault('all_page_ids', set())
                all_page_ids = results['all'].setdefault('page_ids', set())
                all_page_ids.add(answer['page_id'])
                results['all']['test_pages'] = len(all_page_ids)
            add_entry(results1, category)
            #results1['all']['answer_total'] += 1
            add_entry(results2, (category, attribute))
            #results2[('all', 'all')]['answer_total'] += 1

            key = hash(hashes)
            if answers.get(key) is None:
                answers[key] = hashes
                answers_info[key] = answer
            #key = hash((hashes[0], None, hashes[2]))
            key = hash((hashes[0], None, hashes[2], hashes[3]))
            if answers.get(key) is None:
                answers[key] = hashes
                answers_info[key] = answer
            #key = hash((None, hashes[1], hashes[2]))
            key = hash((None, hashes[1], hashes[2], hashes[3]))
            if answers.get(key) is None:
                answers[key] = hashes
                answers_info[key] = answer

            key_nopos = hash(hashes_nopos)
            if answers_nopos.get(key_nopos) is None:
                answers_nopos[key_nopos] = hashes_nopos
                answers_info_nopos[key_nopos] = answer
            key_nopos = hash((hashes_nopos[0], None, hashes_nopos[2], hashes_nopos[3]))
            if answers_nopos.get(key_nopos) is None:
                answers_nopos[key_nopos] = hashes_nopos
                answers_info_nopos[key_nopos] = answer
            key_nopos = hash((None, hashes_nopos[1], hashes_nopos[2], hashes_nopos[3]))
            if answers_nopos.get(key_nopos) is None:
                answers_nopos[key_nopos] = hashes_nopos
                answers_info_nopos[key_nopos] = answer

        #del results1['all']['all_page_ids']
        #del results2['all']['all_page_ids']
        del results1['all']['page_ids']
        del results2['all']['page_ids']
    process_answers()
    #process_answers(results1)
    #process_answers(results2)

    #def process_submissions(results):
    def process_submissions():
        for key, submission_hashes in submissions.items():
            category = submission_hashes[2]
            attribute = submission_hashes[3]
            submission = submissions_info[key]

            def check_entry(results, result_key):
            #def check_entry(results, result_key, all_key):
            #def check_entry(results, result_key, depth=1):
                #all_key = 'all'
                #if depth >= 2:
                #    all_key = ('all',) * depth
                #if category not in results:
                if result_key not in results:
                    #continue
                    #raise Exception('key not in results: ' + str(result_key))
                    return
                #results[category]["submission_total"] += 1
                results[result_key]["submission_total"] += 1
                results["all"]["submission_total"] += 1

                for in_tag in ['in_table', 'in_list', 'in_infobox', 'in_body']:
                    if submission.get(in_tag):
                        results[result_key].setdefault('submissions_'+in_tag, 0)
                        results[result_key]['submissions_' + in_tag] += 1
                        results['all']['submissions_' + in_tag] += 1

                #results[all_key]["submission_total"] += 1
                if answers.get(key) is not None:
                    answer_hashes = answers[key]
                    answer_info = answers_info[key]
                    #results[category]["valid_submission_num"] += 1
                    results[result_key]["valid_submission_num"] += 1
                    results["all"]["valid_submission_num"] += 1
                    #results[all_key]["valid_submission_num"] += 1
                    if submission_hashes[0] is not None and submission_hashes[0] == answer_hashes[0] \
                            or submission_hashes[1] is not None and submission_hashes[1] == answer_hashes[1]:
                        #results[category]["correct_num"] += 1
                        results[result_key]["correct_num"] += 1
                        results["all"]["correct_num"] += 1
                        #results[all_key]["correct_num"] += 1
                        #if answer_info.get('in_table'):
                        #    results[result_key]['correct_in_table'] += 1
                        #    results['all']['correct_in_table'] += 1
                        #if answer_info.get('in_list'):
                        #    results[result_key]['correct_in_list'] += 1
                        #    results['all']['correct_in_list'] += 1
                        #if answer_info.get('in_infobox'):
                        #    results[result_key]['correct_in_infobox'] += 1
                        #    results['all']['correct_in_infobox'] += 1
                        #if answer_info.get('in_body'):
                        #    results[result_key]['correct_in_body'] += 1
                        #    results['all']['correct_in_body'] += 1
                        for in_tag in ['in_table', 'in_list', 'in_infobox', 'in_body']:
                            if answer_info.get(in_tag):
                                #results[result_key].setdefault('correct_'+in_tag, 0)
                                results[result_key]['correct_' + in_tag] += 1
                                results['all']['correct_' + in_tag] += 1

            check_entry(results1, category)
            #check_entry(results1, category, 'all')
            check_entry(results2, (category, attribute))
            #check_entry(results2, (category, attribute), ('all', 'all'))


        for key, submission_hashes in submissions_nopos.items():
            category = submission_hashes[2]
            attribute = submission_hashes[3]

            def check_entry(results, result_key):
                if result_key not in results:
                    return
                results[result_key]["submission_total_nopos"] += 1
                results["all"]["submission_total_nopos"] += 1
                if answers.get(key) is not None:
                    answer_hashes = answers[key]
                    results[result_key]["valid_submission_num_nopos"] += 1
                    results["all"]["valid_submission_num_nopos"] += 1
                    if submission_hashes[0] is not None and submission_hashes[0] == answer_hashes[0] \
                            or submission_hashes[1] is not None and submission_hashes[1] == answer_hashes[1]:
                        results[result_key]["correct_num_nopos"] += 1
                        results["all"]["correct_num_nopos"] += 1
            check_entry(results1, category)
            check_entry(results2, (category, attribute))

    #process_submissions(results1)
    #process_submissions(results2)
    process_submissions()
    results1["macro"]["category_total"] = len(categories)
    #results2["macro"]["category_total"] = len(category_attribute_pairs)
    results2["macro"]["category_attribute_total"] = len(category_attribute_pairs)
    #results2[("macro", "macro")]["category_attribute_total"] = len(category_attribute_pairs)

    #def score_results(results, result_keys):
    #def score_results(results, result_keys, total_key):
    def score_results(results, result_keys):
    #def score_results(results, result_keys, depth=1):
        #for category in categories:
        #all_key = 'all'
        #macro_key = 'macro'
        #if depth >= 2:
        #    all_key = ('all',) * depth
        #    macro_key = ('macro',) * depth
        for result_key in result_keys:
            #results[category]["precision"] = results[category]["correct_num"] / (results[category]["submission_total"] or 1)
            #results[category]["recall"] = results[category]["correct_num"] / results[category]["answer_total"]
            #results[category]["F-measure"] = 2.0 * results[category]["precision"] * results[category]["recall"] \
            #    / (results[category]["precision"] + results[category]["recall"] or 1)
            results[result_key]["precision"] = results[result_key]["correct_num"] / (results[result_key]["submission_total"] or 1)
            results[result_key]["recall"] = results[result_key]["correct_num"] / results[result_key]["answer_total"]
            results[result_key]["F-measure"] = 2.0 * results[result_key]["precision"] * results[result_key]["recall"] \
                / (results[result_key]["precision"] + results[result_key]["recall"] or 1)

            results["macro"]["precision"] += results[result_key]["precision"]
            results["macro"]["recall"] += results[result_key]["recall"]
            results["macro"]["F-measure"] += results[result_key]["F-measure"]

            for tag_type in ['in_table', 'in_list', 'in_infobox', 'in_body']:
                #results[result_key]["precision_" + tag_type] = results[result_key]["correct_" + tag_type] / (results[result_key]["submission_total"] or 1)
                #results[result_key]["recall_" + tag_type] = results[result_key]["correct_" + tag_type] / results[result_key]["answer_total"]
                if results[result_key]['answers_' + tag_type] > 0:
                    results[result_key]["precision_" + tag_type] = results[result_key]["correct_" + tag_type] / (results[result_key]["submissions_" + tag_type] or 1)
                    results[result_key]["recall_" + tag_type] = results[result_key]["correct_" + tag_type] / results[result_key]["answers_" + tag_type]
                    results[result_key]["f_" + tag_type] = 2.0 * results[result_key]["precision_" + tag_type] * results[result_key]["recall_" + tag_type] \
                        / (results[result_key]["precision_" + tag_type] + results[result_key]["recall_" + tag_type] or 1)
                    results["macro"]["f_" + tag_type] += results[result_key]['f_' + tag_type]

            #results[result_key]["precision_in_table"] = results[result_key]["correct_in_table"] / (results[result_key]["submission_total"] or 1)
            #results[result_key]["recall_in_table"] = results[result_key]["correct_in_table"] / (results[result_key]["answers_in_table"] or 1)
            #results[result_key]["f_in_table"] = 2.0 * results[result_key]["precision_in_table"] * results[result_key]["recall_in_table"] \
            #    / (results[result_key]["precision_in_table"] + results[result_key]["recall_in_table"] or 1)
            
            #results[result_key]["precision_in_list"] = results[result_key]["correct_in_list"] / (results[result_key]["submission_total"] or 1)
            #results[result_key]["recall_in_list"] = results[result_key]["correct_in_list"] / (results[result_key]["answers_in_list"] or 1)
            #results[result_key]["f_in_list"] = 2.0 * results[result_key]["precision_in_list"] * results[result_key]["recall_in_list"] \
            #    / (results[result_key]["precision_in_list"] + results[result_key]["recall_in_list"] or 1)
            
            #results[result_key]["precision_in_infobox"] = results[result_key]["correct_in_infobox"] / (results[result_key]["submission_total"] or 1)
            #results[result_key]["recall_in_infobox"] = results[result_key]["correct_in_infobox"] / (results[result_key]["answers_in_infobox"] or 1)
            #results[result_key]["f_in_infobox"] = 2.0 * results[result_key]["precision_in_infobox"] * results[result_key]["recall_in_infobox"] \
            #    / (results[result_key]["precision_in_infobox"] + results[result_key]["recall_in_infobox"] or 1)

            #for tag_type in ['table', 'list', 'infobox']:
            #    results["macro"]["f_in_" + tag_type] = \
            #        results['macro'].get('f_in_' + tag_type, 0) + \
            #        results[result_key]['f_in_' + tag_type]
        
            results[result_key]['error_contribution'] = results[result_key]['answer_total'] * (1 - results[result_key]['F-measure'])
            results['all'].setdefault('error_contribution', 0)
            results['all']['error_contribution'] += results[result_key]['error_contribution']
        #results["macro"]["precision"] /= results["macro"]["category_total"]
        #results["macro"]["recall"] /= results["macro"]["category_total"]
        #results["macro"]["F-measure"] /= results["macro"]["category_total"]
        #results["macro"]["precision"] /= results["macro"][total_key]
        #results["macro"]["recall"] /= results["macro"][total_key]
        #results["macro"]["F-measure"] /= results["macro"][total_key]
        results["macro"]["precision"] /= len(result_keys)
        results["macro"]["recall"] /= len(result_keys)
        results["macro"]["F-measure"] /= len(result_keys)
        results["micro"]["precision"] = results["all"]["correct_num"] / (results["all"]["submission_total"] or 1)
        results["micro"]["recall"] = results["all"]["correct_num"] / results["all"]["answer_total"]
        results["micro"]["F-measure"] = 2.0 * results["micro"]["precision"] * results["micro"]["recall"] \
            / (results["micro"]["precision"] + results["micro"]["recall"] or 1)

        #results["macro"]["f_in_table"] /= len(result_keys)
        #results["macro"]["f_in_infobox"] /= len(result_keys)
        #results["macro"]["f_in_list"] /= len(result_keys)
        if results == results1:
            results["macro"]["f_in_table"] /= len(categories_in_table)
            results["macro"]["f_in_infobox"] /= len(categories_in_infobox)
            results["macro"]["f_in_list"] /= len(categories_in_list)
            results['macro']['f_in_body'] /= len(categories_in_body)
        if results == results2:
            results["macro"]["f_in_table"] /= len(category_attribute_pairs_in_table)
            results["macro"]["f_in_infobox"] /= len(category_attribute_pairs_in_infobox)
            results["macro"]["f_in_list"] /= len(category_attribute_pairs_in_list)
            results['macro']['f_in_body'] /= len(category_attribute_pairs_in_body)

        #for tag_type in ["table", "list", "infobox"]:
        #    results["micro"]["precision_in_" + tag_type] = results["all"]["correct_in_" + tag_type] / (results["all"]["submission_total"] or 1)
        #    results["micro"]["recall_in_" + tag_type] = results["all"]["correct_in_" + tag_type] / (results["all"]["answers_in_" + tag_type] or 1)
        #    results["micro"]["f_in_" + tag_type] = 2.0 * results["micro"]["precision_in_" + tag_type] * results["micro"]["recall_in_" + tag_type] \
        #        / (results["micro"]["precision_in_" + tag_type] + results["micro"]["recall_in_" + tag_type] or 1)
        for tag_type in ['in_table', 'in_list', 'in_infobox', 'in_body']:
            #results["micro"]["precision_" + tag_type] = results["all"]["correct_" + tag_type] / (results["all"]["submission_total"] or 1)
            #results["micro"]["recall_" + tag_type] = results["all"]["correct_" + tag_type] / (results["all"]["answers_" + tag_type] or 1)
            results["micro"]["precision_" + tag_type] = results["all"]["correct_" + tag_type] / (results["all"]["submissions_" + tag_type] or 1)
            results["micro"]["recall_" + tag_type] = results["all"]["correct_" + tag_type] / (results["all"]["answers_" + tag_type] or 1)
            results["micro"]["f_" + tag_type] = 2.0 * results["micro"]["precision_" + tag_type] * results["micro"]["recall_" + tag_type] \
                / (results["micro"]["precision_" + tag_type] + results["micro"]["recall_" + tag_type] or 1)
            #logger.debug('tag_type: %s', tag_type)
            #logger.debug('all correct_' + tag_type + ': ' + str(results["all"]["correct_" + tag_type]))
            #logger.debug('all submission_' + tag_type + ': ' + str(results["all"]["submissions_" + tag_type]))
            #logger.debug('all answers_' + tag_type + ': ' + str(results["all"]["answers_" + tag_type]))
            #logger.debug('result micro precision_' + tag_type + ': ' + str(results["micro"]["precision_" + tag_type]))
            #logger.debug('result micro recall_' + tag_type + ': ' + str(results["micro"]["recall_" + tag_type]))
            #logger.debug('result micro f_' + tag_type + ': ' + str(results["micro"]["f_" + tag_type]))

    score_results(results1, categories)
    score_results(results2, category_attribute_pairs)
    #score_results(results1, categories, 'category_total')
    #score_results(results2, category_attribute_pairs, 'category_attribute_total')
    #return results

    for results in [results1, results2]:
        total_error_contribution = results['all']['error_contribution']
        for key, row in results.items():
            if 'error_contribution' in row:
                row['error_contribution_ratio'] = 100 * row['error_contribution'] / (total_error_contribution or 1)

    return results1, results2


GS_PATH = "./Shinra2022_leaderboard_AExt_GS.jsonl"

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='Shinra scoring program')
        parser.add_argument('--submission_path', help='Submission path')
        parser.add_argument('-a', '--answer_path', default=GS_PATH, help='Answer path')
        parser.add_argument('-d', '--ene_definition', help='ENE definition path')
        parser.add_argument('-t', '--train_path', help='Training data path')
        parser.add_argument('--train-html', help='Training HTML directory path')
        parser.add_argument('--all-html', help='All HTML directory path for evaluation')

        args = parser.parse_args()
        all_html_dir = args.all_html

        # print(evaluate(args.submission_path, args.answer_path))
        #results = evaluate(args.submission_path, args.answer_path)
        results1, results2 = evaluate(args.submission_path, args.answer_path)
        #results1, results2 = evaluate(args.submission_path, args.answer_path, args.all_html)

        #print(json.dumps({
        #    "status": "success",
        #    "scores": [results["macro"]["F-measure"], results["micro"]["F-measure"]],
        #}, ensure_ascii=False, indent=2))

        #logger.debug(results1)
        #logger.debug(results2)
        #results = results1
        results = results2

        ene_id2name = {}
        with open(args.ene_definition, "r") as f:
            for line in f:
                #ene_id2name[line.split("\t")[0]] = line.split("\t")[1].strip()
                d = json.loads(line)
                ene_id2name[d["ENE_id"]] = d["name"]['ja']

        with open(args.train_path) as f:
            train_lines = f.readlines()
            #for i, line in enumerate(tqdm(f)):
            #for i, line in enumerate(train_lines):
            for result in [results1, results2]:
                result['all']['attribute_set'] = set()
                result['all']['page_attribute_set'] = set()
            for i, line in enumerate(tqdm(train_lines)):
                #if SHORT_DEBUG and i > 10000:
                if SHORT_DEBUG and i > SHORT_DEBUG_COUNT:
                    break
                d = json.loads(line)
                ene = d['ENE']
                if not ene:
                    continue
                page_id = d['page_id']
                attribute = d['attribute']
                #attribute_value = d['attribute_value']
                if d.get('text_offset'):
                    attribute_value = d['text_offset']['text']
                #if d.get('html_offset'):
                #    attribute_value = d['html_offset']['text']
                #else:
                #    attribute_value = d['text_offset']['text']

                for results in [results1, results2]:
                    attribute_set = results['all']['attribute_set']
                    attribute_set.add( (attribute,attribute_value) )
                    page_attribute_set = results['all']['page_attribute_set']
                    page_attribute_set.add ( (page_id,attribute,attribute_value) )
                    results['all']['unique_train_attributes'] = len(attribute_set)
                    results['all']['unique_train_page_attributes'] = len(page_attribute_set)
                if ene in results1:
                    #num = results1[ene].get('train_total', 0)
                    num = results1[ene].get('train_samples', 0)
                    #results1[ene]['train_total'] = num + 1
                    results1[ene]['train_samples'] = num + 1
                    page_ids = results1[ene].setdefault('page_ids', set())
                    page_ids.add(d['page_id'])
                    attribute_set = results1[ene].setdefault('attribute_set', set())
                    attribute_set.add( (attribute,attribute_value) )
                    page_attribute_set = results1[ene].setdefault('page_attribute_set', set())
                    page_attribute_set.add( (page_id,attribute,attribute_value) )
                    #results1[ene]['num_pages'] = len(results1[ene]['page_ids'])
                    results1[ene]['train_pages'] = len(page_ids)
                    #results1[ene]['train_samples_per_page'] = results1[ene]['train_total'] / results1[ene]['num_pages']
                    results1[ene]['train_samples_per_page'] = results1[ene]['train_samples'] / results1[ene]['train_pages']
                    results1[ene]['unique_train_attributes'] = len(attribute_set)
                    results1[ene]['unique_train_page_attributes'] = len(page_attribute_set)
                else:
                    #results1[ene] = {'train_total': 1}
                    results1[ene] = {'train_samples': 1}
                    results1[ene]['page_ids'] = set([d['page_id']])
                    results1[ene]['attribute_set'] = set( (attribute,attribute_value) )
                    results1[ene]['page_attribute_set'] = set( (page_id,attribute,attribute_value) )
                    results1[ene]['train_pages'] = 1
                    results1[ene]['train_samples_per_page'] = 1
                    #results1[ene]['unique_train_samples'] = 1
                    results1[ene]['unique_train_attributes'] = 1
                    results1[ene]['unique_train_page_attributes'] = 1
                if (ene, attribute) in results2:
                    #num = results2[(ene, attribute)].get('train_total', 0)
                    num = results2[(ene, attribute)].get('train_samples', 0)
                    #results2[(ene, attribute)]['train_total'] = num + 1
                    results2[(ene, attribute)]['train_samples'] = num + 1
                    page_ids = results2[(ene, attribute)].setdefault('page_ids', set())
                    page_ids.add(d['page_id'])
                    attribute_set = results2[(ene, attribute)].setdefault('attribute_set', set())
                    attribute_set.add( attribute_value )
                    page_attribute_set = results2[(ene, attribute)].setdefault('page_attribute_set', set())
                    page_attribute_set.add( (page_id,attribute_value) )
                    results2[(ene,attribute)]['train_pages'] = len(page_ids)
                    results2[(ene, attribute)]['train_samples_per_page'] = results2[(ene, attribute)]['train_samples'] / results2[(ene, attribute)]['train_pages']
                    results2[(ene, attribute)]['unique_train_attributes'] = len(attribute_set)
                    results2[(ene, attribute)]['unique_train_page_attributes'] = len(page_attribute_set)
                else:
                    #results[ene] = {'train_total': 1}
                    #results2[(ene, attribute)] = {'train_total': 1}
                    results2[(ene, attribute)] = {'train_samples': 1}
                    results2[(ene, attribute)]['page_ids'] = set([d['page_id']])
                    results2[(ene, attribute)]['attribute_set'] = set( attribute_value )
                    results2[(ene, attribute)]['page_attribute_set'] = set( (page_id,attribute_value) )
                    results2[(ene,attribute)]['train_pages'] = 1
                    #results2[(ene,attribute)]['unique_train_samples'] = 1
                    results2[(ene,attribute)]['unique_train_attributes'] = 1
                    results2[(ene,attribute)]['unique_train_page_attributes'] = 1
                if args.train_html:
                    #continue
                    d = check_in_tags(args.train_html, d)
                    #results1[ene].setdefault('train_samples_in_table', 0)
                    #results2[(ene, attribute)].setdefault('train_samples_in_table', 0)
                    #results1[ene].setdefault('train_samples_in_infobox', 0)
                    #results2[(ene, attribute)].setdefault('train_samples_in_infobox', 0)
                    #results1[ene].setdefault('train_samples_in_list', 0)
                    #results2[(ene, attribute)].setdefault('train_samples_in_list', 0)
                    #results1[ene].setdefault('train_samples_in_body', 0)
                    #results2[(ene, attribute)].setdefault('train_samples_in_body', 0)
                    #for results in [results1, results2]:
                    #    results['all'].setdefault('train_samples_in_table', 0)
                    #    results['all'].setdefault('train_samples_in_infobox', 0)
                    #    results['all'].setdefault('train_samples_in_list', 0)
                    #    results['all'].setdefault('train_samples_in_body', 0)
                    #if d['in_table']:
                    #    results1[ene]['train_samples_in_table'] += 1
                    #    results2[(ene, attribute)]['train_samples_in_table'] += 1
                    #if d['in_infobox']:
                    #    results1[ene]['train_samples_in_infobox'] += 1
                    #    results2[(ene, attribute)]['train_samples_in_infobox'] += 1
                    #if d['in_list']:
                    #    results1[ene]['train_samples_in_list'] += 1
                    #    results2[(ene, attribute)]['train_samples_in_list'] += 1
                    #if d['in_body']:
                    #    results1[ene]['train_samples_in_body'] += 1
                    #    results2[(ene, attribute)]['train_samples_in_body'] += 1
                    for in_tag in ['in_table', 'in_infobox', 'in_list', 'in_body']:
                        if d[in_tag]:
                            for results in [results1, results2]:
                                results['all'].setdefault('train_samples_' + in_tag, 0)
                                if d[in_tag]:
                                    results['all']['train_samples_' + in_tag] += 1
                            if d[in_tag]:
                                results1[ene].setdefault('train_samples_' + in_tag, 0)
                                results1[ene]['train_samples_' + in_tag] += 1
                                results2[(ene, attribute)].setdefault('train_samples_' + in_tag, 0)
                                results2[(ene, attribute)]['train_samples_' + in_tag] += 1
                            #results1['all'].setdefault('train_samples_' + in_tag, 0)
                            #results2['all'].setdefault('train_samples_' + in_tag, 0)
                            #results1['all']['train_samples_' + in_tag] += 1
                            #results2['all']['train_samples_' + in_tag] += 1
                            #results1[ene]['train_samples_' + in_tag] += 1
                            #results2[(ene, attribute)]['train_samples_' + in_tag] += 1
                # 集計
                results1['all']['train_samples'] = results1['all'].get('train_samples', 0) + 1
                results2['all']['train_samples'] = results2['all'].get('train_samples', 0) + 1
                all_page_ids = results1['all'].setdefault('page_ids', set())
                all_page_ids.add(d['page_id'])
                results1['all']['train_pages'] = len(all_page_ids)
                results2['all']['train_pages'] = len(all_page_ids)
                train_samples_per_page = results1['all']['train_samples'] / results1['all']['train_pages']
                results1['all']['train_samples_per_page'] = train_samples_per_page
                results2['all']['train_samples_per_page'] = train_samples_per_page
            for results in [results1, results2]:
                del results['all']['attribute_set']
                del results['all']['page_attribute_set']

        #fields = ['Key', 'ENE Ja', 'Attribute', 'precision', 'recall', 'F-measure', 'train_pages', 'train_samples', 'unique_train_page_attributes', 'unique_train_attributes', 'train_samples_in_list', 'train_samples_in_table', 'train_samples_in_infobox', 'train_samples_per_page', 'answer_total', 'test_pages', 'submission_total', 'correct_num', 'answers_in_table', 'answers_in_list', 'answers_in_infobox', 'f_in_table', 'f_in_list', 'f_in_infobox']
        #fields = ['Key', 'ENE Ja', 'Attribute', 'precision', 'recall', 'F-measure', 'train_pages', 'train_samples', 'unique_train_page_attributes', 'unique_train_attributes', 'train_samples_in_list', 'train_samples_in_table', 'train_samples_in_infobox', 'train_samples_per_page', 'answer_total', 'test_pages', 'submission_total', 'correct_num', 'answers_in_table', 'answers_in_list', 'answers_in_infobox', 'f_in_table', 'f_in_list', 'f_in_infobox', 'error_contribution']
        fields = [
            'Key',
            'ENE Ja',
            'Attribute',
            'precision',
            'recall',
            'F-measure',
            'train_pages',
            'train_samples',
            'unique_train_page_attributes',
            'unique_train_attributes',
            'train_samples_in_list',
            'train_samples_in_table',
            'train_samples_in_infobox',
            'train_samples_in_body',
            'train_samples_per_page',
            'answer_total',
            'test_pages',
            'submission_total',
            'correct_num',
            'answers_in_table',
            'answers_in_list',
            'answers_in_infobox',
            'answers_in_body',
            'f_in_table',
            'f_in_list',
            'f_in_infobox',
            'f_in_body',
            'error_contribution',
            'error_contribution_ratio',
        ]
        writer = csv.DictWriter(sys.stdout, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()

        def write_row(key):
            row = results[key]
            if type(key) == tuple:
                ene = key[0]
                attribute = key[1]
            else:
                ene = key
                attribute = ''
            #row['ENE ID'] = key
            row['ENE ID'] = ene
            row['Key'] = ene
            #if key in ene_id2name:
            if ene in ene_id2name:
                #row['ENE Ja'] = ene_id2name[key]
                row['ENE Ja'] = ene_id2name[ene]
                row['Attribute'] = attribute
            #logger.debug(row)
            if 'answer_total' not in row:
                #if row['ENE ID'] not in ['all', 'macro', 'micro']:
                if row['Key'] not in ['all', 'macro', 'micro']:
                    return
            writer.writerow(row)

        logger.debug("results['all']: %s", results['all'])
        logger.debug("results['macro']: %s", results['macro'])
        logger.debug("results['micro']: %s", results['micro'])
        write_row('all')
        write_row('macro')
        write_row('micro')
        del results['all']
        del results['macro']
        del results['micro']
        #for key in sorted(results.keys()):
        for i, key in enumerate(sorted(results.keys())):
        #for i, key in enumerate(sorted(results.keys(), key=lambda k: results[k].get('F-measure', 0), reverse=True)):
            #if i < 10:
            #    logger.debug(key)
            #else:
            #    break
            if key not in ['all', 'macro', 'micro']:
                write_row(key)

    except Exception:
        print(json.dumps({"status": "failure"}, ensure_ascii=False))
        traceback.print_exc()
