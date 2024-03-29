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

LIST_IN_TAGS = ['in_table', 'in_infobox', 'in_other_table', 'in_list', 'in_text']

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
    #logger.debug(soup)
    html_offset = rec['html_offset']
    start_line = html_offset['start']['line_id']
    start_offset = html_offset['start']['offset']
    end_line = html_offset['end']['line_id']
    end_offset = html_offset['end']['offset']
    #logger.debug(lines[start_line][start_offset:end_offset])
    substr1 = str.join('', lines[0:start_line] + [lines[start_line][0:start_offset]]).lower()
    #substr2 = str.join('', [lines[end_line][end_offset:]] + lines[end_line+1:]).lower()
    def check_in_tag(tag, keyword=None):
        start_tag = substr1.rfind(f'<{tag}')
        if start_tag < 0:
            return False
        end_tag = substr1.find(f'</{tag}>', start_tag)
        if end_tag >= 0:
            # 属性値の前で閉じタグがある
            return False
        if keyword:
            if substr1.find(keyword, start_tag) >= 0:
                return True
            else:
                return False
        return True
    rec['in_table'] = check_in_tag('table')
    rec['in_infobox'] = check_in_tag('table', 'infobox')
    rec['in_other_table'] = rec['in_table'] and not rec['in_infobox']
    rec['in_list'] = check_in_tag('ul') or check_in_tag('ol') or check_in_tag('dl')
    rec['in_text'] = not rec['in_table'] and not rec['in_list']
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
            str(json_text["text_offset"]["text"]),
        ))
    if json_text.get("html_offset") is not None:
        html_hash = hash((
            str(json_text["page_id"]),
            str(json_text["ENE"]),
            str(json_text["attribute"]),
            str(json_text["html_offset"]["text"]),
        ))
    return text_hash, html_hash, str(json_text["ENE"]), str(json_text["attribute"])

def calc_f1(precision: float, recall: float) -> float:
    if precision == 0 and recall == 0:
        return 0
    return 2 * precision * recall / (precision + recall)

def evaluate(submission_path: str, answer_path: str) -> Dict[str, Dict[str, float]]:
#def evaluate(submission_path: str, answer_path: str, html_dir) -> Dict[str, Dict[str, float]]:
    #def get_initial_results() -> Dict[str, Dict[str, float]]:
    def get_initial_results() -> Dict[Any, Dict[str, float]]:
        results = {
            "all": {
                "answer_total": 0,
                "submission_total": 0,
                "valid_submission_num": 0,
                "correct_num": 0,
                'answer_total_nopos': 0,
                'submission_total_nopos': 0,
                "valid_submission_num_nopos": 0,
                'correct_num_nopos': 0,
            },
            "macro": {
                "precision": 0,
                "recall": 0,
                "F-measure": 0,
            },
            "micro": {
                "precision": 0,
                "recall": 0,
                "F-measure": 0,
            },
        }
        for in_tag in LIST_IN_TAGS:
            results['all']['answers_' + in_tag] = 0
            results['all']['submissions_' + in_tag] = 0
            results['all']['correct_' + in_tag] = 0
            results['macro']['f1_' + in_tag] = 0
        results['macro']['precision_nopos'] = 0
        results['macro']['recall_nopos'] = 0
        results['macro']['f1_nopos'] = 0
        return results
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
    categories_in_tag: Dict[str, Set[str]] = {}

    category_attribute_pairs = set()
    category_attribute_pairs_in_tag: Dict[str, Set[(str,str)]] = {}

    for in_tag in LIST_IN_TAGS:
        categories_in_tag[in_tag] = set()
        category_attribute_pairs_in_tag[in_tag] = set()

    for submission in submission_list:
        hashes = make_hashes(submission)
        key = hash(hashes)
        if submissions.get(key) is None:
            submissions[key] = hashes
            submissions_info[key] = submission
        # nopos
        hashes_nopos = make_hashes_nopos(submission)
        key_nopos = hash(hashes_nopos)
        if submissions_nopos.get(key_nopos) is None:
            submissions_nopos[key_nopos] = hashes_nopos
            submissions_info_nopos[key_nopos] = submission

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

            for in_tag in LIST_IN_TAGS:
                if answer.get(in_tag):
                    categories_in_tag[in_tag].add(category)
                    category_attribute_pairs_in_tag[in_tag].add( (category,attribute) )

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
                    }
                    for in_tag in LIST_IN_TAGS:
                        results[result_key]['answers_' + in_tag] = 0
                        results[result_key]['submissions_' + in_tag] = 0
                        results[result_key]['correct_' + in_tag] = 0
                else:
                    results[result_key]["answer_total"] += 1
                results["all"]["answer_total"] += 1
                for in_tag in LIST_IN_TAGS:
                    if answer.get(in_tag):
                        results[result_key]['answers_' + in_tag] += 1
                        results['all']['answers_' + in_tag] += 1
                page_ids = results[result_key].setdefault('page_ids', set())
                page_ids.add(answer['page_id'])
                results[result_key]['test_pages'] = len(page_ids)
                all_page_ids = results['all'].setdefault('page_ids', set())
                all_page_ids.add(answer['page_id'])
                results['all']['test_pages'] = len(all_page_ids)
            add_entry(results1, category)
            add_entry(results2, (category, attribute))

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

            added_nopos = False
            key_nopos = hash(hashes_nopos)
            if answers_nopos.get(key_nopos) is None:
                answers_nopos[key_nopos] = hashes_nopos
                answers_info_nopos[key_nopos] = answer
                added_nopos = True
            key_nopos = hash((hashes_nopos[0], None, hashes_nopos[2], hashes_nopos[3]))
            if answers_nopos.get(key_nopos) is None:
                answers_nopos[key_nopos] = hashes_nopos
                answers_info_nopos[key_nopos] = answer
                added_nopos = True
            key_nopos = hash((None, hashes_nopos[1], hashes_nopos[2], hashes_nopos[3]))
            if answers_nopos.get(key_nopos) is None:
                answers_nopos[key_nopos] = hashes_nopos
                answers_info_nopos[key_nopos] = answer
                added_nopos = True
            if added_nopos:
                for results, result_key in [(results1, category), (results2, (category, attribute))]:
                    results[result_key]["answer_total_nopos"] += 1
                    results["all"]["answer_total_nopos"] += 1

        del results1['all']['page_ids']
        del results2['all']['page_ids']
    process_answers()

    def process_submissions():
        for key, submission_hashes in submissions.items():
            category = submission_hashes[2]
            attribute = submission_hashes[3]
            submission = submissions_info[key]

            def check_entry(results, result_key):
                if result_key not in results:
                    return
                results[result_key]["submission_total"] += 1
                results["all"]["submission_total"] += 1

                for in_tag in LIST_IN_TAGS:
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
                        for in_tag in LIST_IN_TAGS:
                            if answer_info.get(in_tag):
                                #results[result_key].setdefault('correct_'+in_tag, 0)
                                results[result_key]['correct_' + in_tag] += 1
                                results['all']['correct_' + in_tag] += 1

            check_entry(results1, category)
            check_entry(results2, (category, attribute))

        for key_nopos, submission_hashes_nopos in submissions_nopos.items():
            category = submission_hashes_nopos[2]
            attribute = submission_hashes_nopos[3]
            #submission = submissions_info_nopos[key_nopos]

            def check_entry(results, result_key):
                if result_key not in results:
                    return
                results[result_key]["submission_total_nopos"] += 1
                results["all"]["submission_total_nopos"] += 1
                if answers_nopos.get(key_nopos) is not None:
                    answer_hashes_nopos = answers_nopos[key_nopos]
                    results[result_key]["valid_submission_num_nopos"] += 1
                    results["all"]["valid_submission_num_nopos"] += 1
                    if submission_hashes_nopos[0] is not None and submission_hashes_nopos[0] == answer_hashes_nopos[0] \
                            or submission_hashes_nopos[1] is not None and submission_hashes_nopos[1] == answer_hashes_nopos[1]:
                        results[result_key]["correct_num_nopos"] += 1
                        results["all"]["correct_num_nopos"] += 1
            check_entry(results1, category)
            check_entry(results2, (category, attribute))

    process_submissions()
    results1["macro"]["category_total"] = len(categories)
    results2["macro"]["category_attribute_total"] = len(category_attribute_pairs)

    def score_results(results, result_keys):
        for result_key in result_keys:

            results[result_key]["precision"] = results[result_key]["correct_num"] / (results[result_key]["submission_total"] or 1)
            results[result_key]["recall"] = results[result_key]["correct_num"] / results[result_key]["answer_total"]
            #results[result_key]["F-measure"] = 2.0 * results[result_key]["precision"] * results[result_key]["recall"] \
            #    / (results[result_key]["precision"] + results[result_key]["recall"] or 1)
            results[result_key]["F-measure"] = calc_f1(results[result_key]["precision"], results[result_key]["recall"])

            results["macro"]["precision"] += results[result_key]["precision"]
            results["macro"]["recall"] += results[result_key]["recall"]
            results["macro"]["F-measure"] += results[result_key]["F-measure"]

            # nopos
            results[result_key]["precision_nopos"] = results[result_key]["correct_num_nopos"] / (results[result_key]["submission_total_nopos"] or 1)
            results[result_key]["recall_nopos"] = results[result_key]["correct_num_nopos"] / results[result_key]["answer_total_nopos"]
            #results[result_key]["f_nopos"] = 2.0 * results[result_key]["precision_nopos"] * results[result_key]["recall_nopos"] \
            #    / (results[result_key]["precision_nopos"] + results[result_key]["recall_nopos"] or 1)
            results[result_key]['f1_nopos'] = calc_f1(results[result_key]["precision_nopos"], results[result_key]["recall_nopos"])
            results["macro"]["precision_nopos"] += results[result_key]["precision_nopos"]
            results["macro"]["recall_nopos"] += results[result_key]["recall_nopos"]
            results["macro"]["f1_nopos"] += results[result_key]["f1_nopos"]

            for tag_type in LIST_IN_TAGS:
                if results[result_key]['answers_' + tag_type] > 0:
                    results[result_key]["precision_" + tag_type] = results[result_key]["correct_" + tag_type] / (results[result_key]["submissions_" + tag_type] or 1)
                    results[result_key]["recall_" + tag_type] = results[result_key]["correct_" + tag_type] / results[result_key]["answers_" + tag_type]
                    #results[result_key]["f_" + tag_type] = 2.0 * results[result_key]["precision_" + tag_type] * results[result_key]["recall_" + tag_type] \
                    #    / (results[result_key]["precision_" + tag_type] + results[result_key]["recall_" + tag_type] or 1)
                    results[result_key]['f1_' + tag_type] = calc_f1(results[result_key]["precision_" + tag_type], results[result_key]["recall_" + tag_type])
                    results["macro"]["f1_" + tag_type] += results[result_key]['f1_' + tag_type]

            results[result_key]['error_contribution'] = results[result_key]['answer_total'] * (1 - results[result_key]['F-measure'])
            results['all'].setdefault('error_contribution', 0)
            results['all']['error_contribution'] += results[result_key]['error_contribution']

        results["macro"]["precision"] /= len(result_keys)
        results["macro"]["recall"] /= len(result_keys)
        results["macro"]["F-measure"] /= len(result_keys)
        results["micro"]["precision"] = results["all"]["correct_num"] / (results["all"]["submission_total"] or 1)
        results["micro"]["recall"] = results["all"]["correct_num"] / results["all"]["answer_total"]
        #results["micro"]["F-measure"] = 2.0 * results["micro"]["precision"] * results["micro"]["recall"] \
        #    / (results["micro"]["precision"] + results["micro"]["recall"] or 1)
        results['micro']['F-measure'] = calc_f1(results["micro"]["precision"], results["micro"]["recall"])

        # nopos
        results['macro']['precision_nopos'] /= len(result_keys)
        results['macro']['recall_nopos'] /= len(result_keys)
        results['macro']['f1_nopos'] /= len(result_keys)
        results['micro']['precision_nopos'] = results['all']['correct_num_nopos'] / (results['all']['submission_total_nopos'] or 1)
        results['micro']['recall_nopos'] = results['all']['correct_num_nopos'] / results['all']['answer_total_nopos']
        results['micro']['f1_nopos'] = calc_f1(results['micro']['precision_nopos'], results['micro']['recall_nopos'])

        for in_tag in LIST_IN_TAGS:
            if results == results1:
                results["macro"]["f1_" + in_tag] /= len(categories_in_tag[in_tag])
            if results == results2:
                results["macro"]["f1_" + in_tag] /= len(category_attribute_pairs_in_tag[in_tag])

        for tag_type in LIST_IN_TAGS:
            results["micro"]["precision_" + tag_type] = results["all"]["correct_" + tag_type] / (results["all"]["submissions_" + tag_type] or 1)
            results["micro"]["recall_" + tag_type] = results["all"]["correct_" + tag_type] / (results["all"]["answers_" + tag_type] or 1)
            results["micro"]["f1_" + tag_type] = 2.0 * results["micro"]["precision_" + tag_type] * results["micro"]["recall_" + tag_type] \
                / (results["micro"]["precision_" + tag_type] + results["micro"]["recall_" + tag_type] or 1)

    score_results(results1, categories)
    score_results(results2, category_attribute_pairs)

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

                    for in_tag in LIST_IN_TAGS:
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
            'precision_nopos',
            'recall_nopos',
            'f1_nopos',
            'train_pages',
            'train_samples',
            'unique_train_page_attributes',
            'unique_train_attributes',
            'train_samples_in_table',
            'train_samples_in_infobox',
            'train_samples_in_other_table',
            'train_samples_in_list',
            'train_samples_in_text',
            'train_samples_per_page',
            'test_pages',
            'answer_total',
            'submission_total',
            'correct_num',
            'answer_total_nopos',
            'submission_total_nopos',
            'correct_num_nopos',
            'answers_in_table',
            'answers_in_infobox',
            'answers_in_other_table',
            'answers_in_list',
            'answers_in_text',
            'f1_in_table',
            'f1_in_infobox',
            'f1_in_other_table',
            'f1_in_list',
            'f1_in_text',
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
