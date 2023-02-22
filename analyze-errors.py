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

all_html_dir = None

def load_json(path: str) -> List[Dict]:
    print(path, file=sys.stderr)
    with open(path, "r", encoding="utf-8-sig") as f:
        #return [json.loads(line) for line in f.readlines()]
        lines = f.readlines()
        records = []
        for i, line in enumerate(tqdm(lines)):
            #if i > 1000:
            #    break
        #if all_html_dir:
        #    return [check_in_tag(all_html_dir, json.loads(line)) for line in f.readlines()]
        #else:
        #    return [json.loads(line) for line in f.readlines()]
            rec = json.loads(line)
            if all_html_dir:
                rec = check_in_tag(all_html_dir, rec)
            records.append(rec)
        return records

def check_in_tag(html_dir, rec):
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
    #end_table_pos = substr2.find('</table>')
    #if end_table_pos >= 0:
    #    if substr2[:end_table_pos].find('<table') >= 0:
    #        pass # 属性値の後に別のテーブルがある（属性値はテーブルに囲まれていない）
    #    else:
    #        #results['train_samples_in_table'] += 1
    #        results1[ene]['train_samples_in_table'] += 1
    #        results2[(ene,attribute)]['train_samples_in_table'] += 1
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
    rec['in_list'] = check_in_tag('ul')
    rec['in_infobox'] = check_in_tag('table', 'infobox')
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


def evaluate(submission_path: str, answer_path: str) -> Dict[str, Dict[str, float]]:
#def evaluate(submission_path: str, answer_path: str, html_dir) -> Dict[str, Dict[str, float]]:
    #results: Dict[str, Dict[str, float]] = {
    results1: Dict[str, Dict[str, float]] = {
        "all": {
            "answer_total": 0,
            "submission_total": 0,
            "valid_submission_num": 0,
            "correct_num": 0,
            'answers_in_table': 0,
            'answers_in_list': 0,
            'answers_in_infobox': 0,
            'correct_in_table': 0,
            'correct_in_list': 0,
            'correct_in_infobox': 0,
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
        }
    }
    results2 = {
        "all": {
            "answer_total": 0,
            "submission_total": 0,
            "valid_submission_num": 0,
            "correct_num": 0,
            'answers_in_table': 0,
            'answers_in_list': 0,
            'answers_in_infobox': 0,
            'correct_in_table': 0,
            'correct_in_list': 0,
            'correct_in_infobox': 0,
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
        }
    }
    submission_list: List[Dict] = load_json(submission_path)
    answer_list: List[Dict] = load_json(answer_path)

    answer_page_ids = set([answer["page_id"] for answer in answer_list])
    submission_list = [submission for submission in submission_list if submission["page_id"] in answer_page_ids]

    #submissions: Dict[int, Tuple[Optional[int], Optional[int], str]] = {}
    #answers: Dict[int, Tuple[Optional[int], Optional[int], str]] = {}
    submissions: Dict[int, Tuple[Optional[int], Optional[int], str, str]] = {}
    answers: Dict[int, Tuple[Optional[int], Optional[int], str, str]] = {}
    answers_info = {}
    categories: Set[str] = set()
    attributes: Set[str] = set()
    category_attribute_pairs = set()
    for submission in submission_list:
        hashes = make_hashes(submission)
        key = hash(hashes)
        if submissions.get(key) is None:
            submissions[key] = hashes

    #def process_answers(results):
    def process_answers():
        for answer in answer_list:
            hashes = make_hashes(answer)
            category = hashes[2]
            attribute = hashes[3]
            categories.add(category)
            attributes.add(attribute)
            category_attribute_pairs.add((category, attribute))

            def add_entry(results, result_key):
                #if results.get(category) is None:
                if results.get(result_key) is None:
                    #results[category] = {
                    results[result_key] = {
                        "answer_total": 1,
                        "submission_total": 0,
                        "valid_submission_num": 0,
                        "correct_num": 0,
                    }
                    results[result_key]['answers_in_table'] = 0
                    results[result_key]['answers_in_list'] = 0
                    results[result_key]['answers_in_infobox'] = 0
                    results[result_key]['correct_in_table'] = 0
                    results[result_key]['correct_in_list'] = 0
                    results[result_key]['correct_in_infobox'] = 0
                else:
                    #results[category]["answer_total"] += 1
                    results[result_key]["answer_total"] += 1
                    #if html_dir:
                    #    results[result_key]['answers_in_table'] += info['in_table']
                    #    results[result_key]['answers_in_list'] += info['in_list']
                    #    results[result_key]['answers_in_infobox'] += info['in_infobox']
                results["all"]["answer_total"] += 1
                if answer.get('in_table'):
                    results[result_key]['answers_in_table'] += 1
                    results['all']['answers_in_table'] += 1
                if answer.get('in_list'):
                    results[result_key]['answers_in_list'] += 1
                    results['all']['answers_in_list'] += 1
                if answer.get('in_infobox'):
                    results[result_key]['answers_in_infobox'] += 1
                    results['all']['answers_in_infobox'] += 1
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
    process_answers()
    #process_answers(results1)
    #process_answers(results2)

    #def process_submissions(results):
    def process_submissions():
        for key, submission_hashes in submissions.items():
            category = submission_hashes[2]
            attribute = submission_hashes[3]

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
                        if answer_info.get('in_table'):
                            results[result_key]['correct_in_table'] += 1
                            results['all']['correct_in_table'] += 1
                        if answer_info.get('in_list'):
                            results[result_key]['correct_in_list'] += 1
                            results['all']['correct_in_list'] += 1
                        if answer_info.get('in_infobox'):
                            results[result_key]['correct_in_infobox'] += 1
                            results['all']['correct_in_infobox'] += 1
            check_entry(results1, category)
            #check_entry(results1, category, 'all')
            check_entry(results2, (category, attribute))
            #check_entry(results2, (category, attribute), ('all', 'all'))
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
            
            results[result_key]["precision_in_table"] = results[result_key]["correct_in_table"] / (results[result_key]["submission_total"] or 1)
            results[result_key]["recall_in_table"] = results[result_key]["correct_in_table"] / (results[result_key]["answers_in_table"] or 1)
            results[result_key]["f_in_table"] = 2.0 * results[result_key]["precision_in_table"] * results[result_key]["recall_in_table"] \
                / (results[result_key]["precision_in_table"] + results[result_key]["recall_in_table"] or 1)
            
            results[result_key]["precision_in_list"] = results[result_key]["correct_in_list"] / (results[result_key]["submission_total"] or 1)
            results[result_key]["recall_in_list"] = results[result_key]["correct_in_list"] / (results[result_key]["answers_in_list"] or 1)
            results[result_key]["f_in_list"] = 2.0 * results[result_key]["precision_in_list"] * results[result_key]["recall_in_list"] \
                / (results[result_key]["precision_in_list"] + results[result_key]["recall_in_list"] or 1)
            
            results[result_key]["precision_in_infobox"] = results[result_key]["correct_in_infobox"] / (results[result_key]["submission_total"] or 1)
            results[result_key]["recall_in_infobox"] = results[result_key]["correct_in_infobox"] / (results[result_key]["answers_in_infobox"] or 1)
            results[result_key]["f_in_infobox"] = 2.0 * results[result_key]["precision_in_infobox"] * results[result_key]["recall_in_infobox"] \
                / (results[result_key]["precision_in_infobox"] + results[result_key]["recall_in_infobox"] or 1)

            results["macro"]["precision"] += results[result_key]["precision"]
            results["macro"]["recall"] += results[result_key]["recall"]
            results["macro"]["F-measure"] += results[result_key]["F-measure"]
            #results[macro_key]["precision"] += results[result_key]["precision"]
            #results[macro_key]["recall"] += results[result_key]["recall"]
            #results[macro_key]["F-measure"] += results[result_key]["F-measure"]
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
    score_results(results1, categories)
    score_results(results2, category_attribute_pairs)
    #score_results(results1, categories, 'category_total')
    #score_results(results2, category_attribute_pairs, 'category_attribute_total')
    #return results
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
            for i, line in enumerate(tqdm(train_lines)):
                #if i > 10000:
                #    break
                d = json.loads(line)
                ene = d['ENE']
                if not ene:
                    continue
                #attribute = d['attribute']
                attribute = d['attribute']
                #if ene in results:
                #    num = results[ene].get('train_total', 0)
                #    #results[ene]['train_total'] = num + 1
                #    results1[ene]['train_total'] = num + 1
                #    results2[(ene,attribute)]['train_total'] = num + 1
                #else:
                #    results[ene] = {'train_total': 1}
                if ene in results1:
                    #num = results1[ene].get('train_total', 0)
                    num = results1[ene].get('train_samples', 0)
                    #results1[ene]['train_total'] = num + 1
                    results1[ene]['train_samples'] = num + 1
                    page_ids = results1[ene].setdefault('page_ids', set())
                    page_ids.add(d['page_id'])
                    #results1[ene]['num_pages'] = len(results1[ene]['page_ids'])
                    results1[ene]['train_pages'] = len(results1[ene]['page_ids'])
                    #results1[ene]['train_samples_per_page'] = results1[ene]['train_total'] / results1[ene]['num_pages']
                    results1[ene]['train_samples_per_page'] = results1[ene]['train_samples'] / results1[ene]['train_pages']
                else:
                    #results1[ene] = {'train_total': 1}
                    results1[ene] = {'train_samples': 1}
                    results1[ene]['page_ids'] = set([d['page_id']])
                    #results1[ene]['num_pages'] = 1
                    results1[ene]['train_pages'] = 1
                    results1[ene]['train_samples_per_page'] = 1
                if (ene, attribute) in results2:
                    #num = results2[(ene, attribute)].get('train_total', 0)
                    num = results2[(ene, attribute)].get('train_samples', 0)
                    #results2[(ene, attribute)]['train_total'] = num + 1
                    results2[(ene, attribute)]['train_samples'] = num + 1
                    page_ids = results2[(ene, attribute)].setdefault('page_ids', set())
                    page_ids.add(d['page_id'])
                    #results2[(ene,attribute)]['num_pages'] = len(results2[(ene,attribute)]['page_ids'])
                    results2[(ene,attribute)]['train_pages'] = len(results2[(ene,attribute)]['page_ids'])
                    #results2[((ene, attribute))]['train_samples_per_page'] = results2[(ene, attribute)]['train_total'] / results2[(ene, attribute)]['num_pages']
                    #results2[((ene, attribute))]['train_samples_per_page'] = results2[(ene, attribute)]['train_total'] / results2[(ene, attribute)]['train_pages']
                    results2[((ene, attribute))]['train_samples_per_page'] = results2[(ene, attribute)]['train_samples'] / results2[(ene, attribute)]['train_pages']
                else:
                    #results[ene] = {'train_total': 1}
                    #results2[(ene, attribute)] = {'train_total': 1}
                    results2[(ene, attribute)] = {'train_samples': 1}
                    results2[(ene, attribute)]['page_ids'] = set([d['page_id']])
                    #results2[(ene,attribute)]['num_pages'] = 1
                    results2[(ene,attribute)]['train_pages'] = 1
                if args.train_html:
                    #continue
                    d = check_in_tag(args.train_html, d)
                    results1[ene].setdefault('train_samples_in_table', 0)
                    results2[(ene, attribute)].setdefault('train_samples_in_table', 0)
                    results1[ene].setdefault('train_samples_in_list', 0)
                    results2[(ene, attribute)].setdefault('train_samples_in_list', 0)
                    results1[ene].setdefault('train_samples_in_infobox', 0)
                    results2[(ene, attribute)].setdefault('train_samples_in_infobox', 0)
                    if d['in_table']:
                        results1[ene]['train_samples_in_table'] += 1
                        results2[(ene, attribute)]['train_samples_in_table'] += 1
                    if d['in_list']:
                        results1[ene]['train_samples_in_list'] += 1
                        results2[(ene, attribute)]['train_samples_in_list'] += 1
                    if d['in_infobox']:
                        results1[ene]['train_samples_in_infobox'] += 1
                        results2[(ene, attribute)]['train_samples_in_infobox'] += 1

                    #text = open(args.train_html + '/' + d['page_id'] + '.html').read()
                    #lines = text.splitlines()
                    ##soup = BeautifulSoup(text, 'html.parser')
                    ##logger.debug(soup)
                    ##results.setdefault('train_samples_in_table', 0)
                    #results1[ene].setdefault('train_samples_in_table', 0)
                    #results2[(ene, attribute)].setdefault('train_samples_in_table', 0)
                    #results1[ene].setdefault('train_samples_in_list', 0)
                    #results2[(ene, attribute)].setdefault('train_samples_in_list', 0)
                    #results1[ene].setdefault('train_samples_in_infobox', 0)
                    #results2[(ene, attribute)].setdefault('train_samples_in_infobox', 0)
                    #html_offset = d['html_offset']
                    #start_line = html_offset['start']['line_id']
                    #start_offset = html_offset['start']['offset']
                    #end_line = html_offset['end']['line_id']
                    #end_offset = html_offset['end']['offset']
                    ##logger.debug(lines[start_line][start_offset:end_offset])
                    #substr1 = str.join('', lines[0:start_line] + [lines[start_line][0:start_offset]]).lower()
                    ##substr2 = str.join('', [lines[end_line][end_offset:]] + lines[end_line+1:]).lower()
                    ##end_table_pos = substr2.find('</table>')
                    ##if end_table_pos >= 0:
                    ##    if substr2[:end_table_pos].find('<table') >= 0:
                    ##        pass # 属性値の後に別のテーブルがある（属性値はテーブルに囲まれていない）
                    ##    else:
                    ##        #results['train_samples_in_table'] += 1
                    ##        results1[ene]['train_samples_in_table'] += 1
                    ##        results2[(ene,attribute)]['train_samples_in_table'] += 1
                    #def check_in_tag(tag, keyword=None):
                    #    #end_table_tag = substr2.find(f'</{tag}>')
                    #    #if end_table_tag < 0:
                    #    #    return False
                    #    #if substr2[:end_table_tag].find(f'<{tag}') >= 0:
                    #    #    return True
                    #    start_tag = substr1.rfind(f'<{tag}')
                    #    if start_tag < 0:
                    #        return False
                    #    end_tag = substr1.find(f'</{tag}>', start_tag)
                    #    if end_tag >= 0:
                    #        # 属性値の前で閉じタグがある
                    #        return False
                    #    if keyword:
                    #        #tag = substr1[start_tag:end_tag+len(tag)+2]
                    #        #logger.debug(start_tag)
                    #        #logger.debug(end_tag)
                    #        #logger.debug(tag)
                    #        #if tag.find(keyword) >= 0:
                    #        if substr1.find(keyword, start_tag) >= 0:
                    #            return True
                    #        else:
                    #            return False
                    #    return True
                    #if check_in_tag('table'):
                    #    results1[ene]['train_samples_in_table'] += 1
                    #    results2[(ene,attribute)]['train_samples_in_table'] += 1
                    #if check_in_tag('ul') or check_in_tag('ol'):
                    #    results1[ene]['train_samples_in_list'] += 1
                    #    results2[(ene,attribute)]['train_samples_in_list'] += 1
                    #if check_in_tag('table', 'infobox'):
                    #    results1[ene]['train_samples_in_infobox'] += 1
                    #    results2[(ene,attribute)]['train_samples_in_infobox'] += 1
                    ##EXIT

        #fields = ['T', 'answer_total', 'submission_total', 'valid_submission_num', 'correct_num', 'precision', 'recall', 'F-measure']
        #fields = ['ENE ID', 'ENE Ja', 'answer_total', 'submission_total', 'valid_submission_num', 'correct_num', 'precision', 'recall', 'F-measure']
        #fields = ['ENE ID', 'ENE Ja', 'answer_total', 'submission_total', 'correct_num', 'precision', 'recall', 'F-measure']
        #fields = ['ENE ID', 'ENE Ja', 'train_total', 'answer_total', 'submission_total', 'correct_num', 'precision', 'recall', 'F-measure']
        #fields = ['ENE ID', 'ENE Ja', 'precision', 'recall', 'F-measure', 'train_total', 'num_pages', 'train_samples_per_page', 'answer_total', 'submission_total', 'correct_num']
        #fields = ['ENE ID', 'ENE Ja', 'Attribute', 'precision', 'recall', 'F-measure', 'train_total', 'answer_total', 'submission_total', 'correct_num']
        #fields = ['ENE ID', 'ENE Ja', 'Attribute', 'precision', 'recall', 'F-measure', 'train_total', 'num_pages', 'train_samples_per_page', 'num_pages', 'answer_total', 'submission_total', 'correct_num']
        #fields = ['ENE ID', 'ENE Ja', 'Attribute', 'precision', 'recall', 'F-measure', 'train_total', 'num_pages', 'train_samples_per_page', 'train_samples_in_table', 'num_pages', 'answer_total', 'submission_total', 'correct_num']
        #fields = ['ENE ID', 'ENE Ja', 'Attribute', 'precision', 'recall', 'F-measure', 'train_pages', 'train_samples', 'train_samples_in_list', 'train_samples_in_table', 'train_samples_in_infobox', 'train_samples_per_page', 'answer_total', 'submission_total', 'correct_num']
        #fields = ['ENE ID', 'ENE Ja', 'Attribute', 'precision', 'recall', 'F-measure', 'train_pages', 'train_samples', 'train_samples_in_list', 'train_samples_in_table', 'train_samples_in_infobox', 'train_samples_per_page', 'answer_total', 'submission_total', 'correct_num', 'answers_in_table', 'answers_in_list', 'answers_in_infobox']
        fields = ['ENE ID', 'ENE Ja', 'Attribute', 'precision', 'recall', 'F-measure', 'train_pages', 'train_samples', 'train_samples_in_list', 'train_samples_in_table', 'train_samples_in_infobox', 'train_samples_per_page', 'answer_total', 'submission_total', 'correct_num', 'answers_in_table', 'answers_in_list', 'answers_in_infobox', 'f_in_table', 'f_in_list', 'f_in_infobox']
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
            #if key in ene_id2name:
            if ene in ene_id2name:
                #row['ENE Ja'] = ene_id2name[key]
                row['ENE Ja'] = ene_id2name[ene]
                row['Attribute'] = attribute
            #logger.debug(row)
            if 'answer_total' not in row:
                return
            writer.writerow(row)

        logger.debug(results['all'])
        #write_row('all')
        #write_row('macro')
        #write_row('micro')
        del results['all']
        del results['macro']
        del results['micro']
        #for key in sorted(results.keys()):
        #for i, key in enumerate(sorted(results.keys())):
        #for i, key in enumerate(sorted(results.keys(), key=lambda k: results[k].get('F-measure', 0), reverse=True)):
        for i, key in enumerate(sorted(results.keys(), key=lambda k: results[k].get('train_total', 0), reverse=True)):
            #if i < 10:
            #    logger.debug(key)
            #else:
            #    break
            if key not in ['all', 'macro', 'micro']:
                write_row(key)

    except Exception:
        print(json.dumps({"status": "failure"}, ensure_ascii=False))
        traceback.print_exc()
