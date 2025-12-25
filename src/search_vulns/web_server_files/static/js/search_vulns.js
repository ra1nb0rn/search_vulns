
var curVulnData = {}, curEOLData = {}, onlyShowTheseVulns = null;
var exploit_url_show_max_length = 52, exploit_url_show_max_length_md = 42;
var ignoreGeneralProductVulns = false, onlyShowEDBExploits = false, showGHSAVulns = false;
var showSingleVersionVulns = false, isGoodProductID = true, showPatchedVulns = true, showTableFiltering = false;
var noVulnsFoundHtml = '<div class="w-full text-center"><h5 class="text-success">No known vulnerabilities could be found.</h5></div>';
var filterVulnDropdownButtonHtml = `<div class="items-center flex-row mb-2 w-full"><button class="btn btn-sm btn-neutral sm:mr-1 md:mr-2 w-14" id="filterVulnsAll" onclick="changeFilterVulns(this)">All</button><button class="btn btn-sm btn-neutral w-auto" id="filterVulnsNone" onclick="changeFilterVulns(this)">None</button></div>`;
var iconUnsorted = '<i class="fa-solid fa-sort"></i>';
var iconSortDesc = '<i class="fa-solid fa-sort-down"></i>';
var iconSortAsc = '<i class="fa-solid fa-sort-up"></i>';
var exportIcon = `<i class="fa-solid fa-clipboard"></i>`, exportIconSuccess = `<i class="fa-solid fa-clipboard-check text-success"></i>`;
var curSortColIdx = 1, curSortColAsc = false, searchIgnoreNextKeyup = false;
var doneTypingQueryTimer, queryInput = $('#query'), doneTypingQueryInterval = 600;  //time in ms
let arrowKeyUpDownInterval = null, arrowKeyUpDownIntervalTime = 100, arrowKeyUpDownHoldDetectionTimer = null, arrowKeyUpDownHoldDetectionTime = 150;
var curSelectedProductIDSuggestion = -1, suggestedQueriesJustOpened = false;


function htmlEntities(text) {
    return text.replace(/[\u00A0-\u9999<>\&"']/g, function (c) {
        return '&#' + c.charCodeAt(0) + ';';
    });
}

function escapeMarkdownSimple(text) {
    return text.replace(/[\\|*_\[\]`]/g, function (c) {
        return '\\' + c;
    });
}

function escapeCSV(text) {
    if (typeof text !== 'string')
        text = `${text}`;
    text = text.replaceAll('"', '""');
    if (['=', '+', '-', '@'].some(c => text.startsWith(c)))
        text = "'" + text;
    if (text.includes(',') || text.includes('"'))
        text = `"${text}"`;
    return text;
}

function reduceToEDBUrls(allUrls) {
    var edb_urls = [];
    for (var i = 0; i < allUrls.length; i++) {
        if (allUrls[i].startsWith('https://www.exploit-db.com/exploits/'))
            edb_urls.push(allUrls[i]);
    }
    return edb_urls;
}

function getCurrentVulnsSorted() {
    var vulns = Object.values(curVulnData);
    if (curSortColIdx == 0) {  // Vuln ID
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                return vuln1.id.localeCompare(vuln2.id);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                return vuln1.id.localeCompare(vuln2.id);
            }).reverse();

        }
    }
    else if (curSortColIdx == 1) {  // CVSS
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                return parseFloat(vuln1.cvss) - parseFloat(vuln2.cvss);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                return parseFloat(vuln2.cvss) - parseFloat(vuln1.cvss);
            });
        }
    }
    else if (curSortColIdx == 2) {  // EPSS
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                return parseFloat(vuln1.epss) - parseFloat(vuln2.epss);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                return parseFloat(vuln2.epss) - parseFloat(vuln1.epss);
            });
        }
    }
    else if (curSortColIdx == 4) {  // Exploits
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                var exploits1 = vuln1.exploits || [];
                var exploits2 = vuln2.exploits || [];

                if (onlyShowEDBExploits) {
                    exploits1 = reduceToEDBUrls(exploits1);
                    exploits2 = reduceToEDBUrls(exploits2);
                }

                return parseInt(exploits1.length) - parseInt(exploits2.length);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                var exploits1 = vuln1.exploits || [];
                var exploits2 = vuln2.exploits || [];

                if (onlyShowEDBExploits) {
                    exploits1 = reduceToEDBUrls(exploits1);
                    exploits2 = reduceToEDBUrls(exploits2);
                }

                return parseInt(exploits2.length) - parseInt(exploits1.length);
            });
        }
    }
}

function createVulnTableRowHtml(idx, vuln) {
    var vuln_row_html = '', vuln_style_class = '', vuln_flag_html = '', vuln_id_html = '';
    var exploits, cvss, cvss_badge_css, epss, epss_badge_css, exploit_url_show;
    var vuln_id_ref_map = vuln.aliases;
    var selectedColumns = JSON.parse(localStorage.getItem('vulnTableColumns'))
    var isVulnUnconfirmed = false, backgroundColorClass = "";

    if (selectedColumns.length < 1)
        return '';

    for (const vuln_id in vuln_id_ref_map) {
        if (vuln_id.startsWith('GHSA') && !showGHSAVulns)
            continue
        vuln_id_html += `<a href="${htmlEntities(vuln_id_ref_map[vuln_id])}" target="_blank" style="color: inherit;">${htmlEntities(vuln_id)}&nbsp;&nbsp;<i class="fa-solid fa-up-right-from-square" style="font-size: 0.92rem"></i></a><br>`;
        if (vuln.match_reason != "vuln_id" && showGHSAVulns && vuln_id.startsWith('GHSA-') && vuln.id.startsWith('CVE-') && !vuln.match_sources.includes('ghsa'))
            isVulnUnconfirmed = true;
    }
    vuln_id_html = vuln_id_html.slice(0, -4);  // strip trailing "<br>"

    if (vuln.match_reason == "general_product_uncertain" || vuln.match_reason == "single_higher_version" || vuln.match_reason == "n_a" || isVulnUnconfirmed) {
        vuln_style_class += "uncertain-vuln text-base-content/75";
        backgroundColorClass = "bg-warning/15";
    }
    if (vuln.cisa_known_exploited) {
        vuln_style_class += " exploited-vuln text-base-content";
        backgroundColorClass = "exploited-vuln-bg";
    }
    if (vuln.reported_patched_by.length > 0) {
        vuln_style_class += "  patched-vuln text-base-content/75";  // overwrites color of previous
        backgroundColorClass = "bg-info/25";
    }
    vuln_style_class += " " + backgroundColorClass;

    vuln_row_html += `<tr class="${vuln_style_class} border-none">`;

    if (selectedColumns.includes('cve')) {
        vuln_row_html += `<td class="text-nowrap whitespace-nowrap pr-2 relative">` + vuln_id_html;
        if (vuln.match_reason == "general_product_uncertain")
            vuln_flag_html += `<br><center><span class="vuln-flag-icon" data-tooltip-target="tooltip-general-${idx}" data-tooltip-placement="bottom"><i class="fas fa-info-circle text-warning"></i></span><div id="tooltip-general-${idx}" role="tooltip" class="tooltip relative z-10 w-80 p-2 text-sm invisible rounded-lg shadow-sm opacity-0 bg-base-300" style="white-space:pre-wrap">This vulnerability affects the queried software in general and could be a false positive.<div class="tooltip-arrow" data-popper-arrow></div></div>`;
        if (vuln.match_reason == "single_higher_version") {
            if (!vuln_flag_html)
                vuln_flag_html += `<br><center><span class="vuln-flag-icon" `;
            else
                vuln_flag_html += '<span class="ml-2 vuln-flag-icon" ';
            vuln_flag_html += `data-tooltip-target="tooltip-single-${idx}" data-tooltip-placement="bottom"><i class="fas fa-info-circle text-warning"></i></span><div id="tooltip-single-${idx}" role="tooltip" class="tooltip relative z-10 w-80 p-2 text-sm invisible rounded-lg shadow-sm opacity-0 bg-base-300" style="white-space:pre-wrap">This vulnerability affects only a single higher version of the product and could be a false positive.<div class="tooltip-arrow" data-popper-arrow></div></div>`;
        }
        if (isVulnUnconfirmed) {
            if (!vuln_flag_html)
                vuln_flag_html += `<br><center><span class="vuln-flag-icon" `;
            else
                vuln_flag_html += '<span class="ml-2 vuln-flag-icon" ';
            vuln_flag_html += `data-tooltip-target="tooltip-unconfirmed-${idx}" data-tooltip-placement="bottom"><i class="fas fa-info-circle text-warning"></i></span><div id="tooltip-unconfirmed-${idx}" role="tooltip" class="tooltip relative z-10 w-80 p-2 text-sm invisible rounded-lg shadow-sm opacity-0 bg-base-300" style="white-space:pre-wrap">The GHSA also tracks this vulnerability, but does not list the queried software as affected.<div class="tooltip-arrow" data-popper-arrow></div></div>`;
        }

        if (vuln.cisa_known_exploited) {
            if (!vuln_flag_html)
                vuln_flag_html += `<br><center><span class="vuln-flag-icon" `;
            else
                vuln_flag_html += '<span class="ml-2 vuln-flag-icon" ';
            vuln_flag_html += `data-tooltip-target="tooltip-exploit-${idx}" data-tooltip-placement="bottom"><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${vuln["id"]}&field_date_added_wrapper=all&sort_by=field_date_added&items_per_page=20" target="_blank"><i class="fa-solid fa-skull text-exploited"></i></a></span><div id="tooltip-exploit-${idx}" role="tooltip" class="tooltip relative z-10 w-80 p-2 text-sm invisible rounded-lg shadow-sm opacity-0 bg-base-300" style="white-space:pre-wrap">This vulnerability has been exploited in the wild according to CISA.<div class="tooltip-arrow" data-popper-arrow></div></div>`;
        }
        if (vuln.reported_patched_by.length > 0) {
            if (!vuln_flag_html)
                vuln_flag_html += `<br><center><span class="vuln-flag-icon" `;
            else
                vuln_flag_html += '<span class="ml-2 vuln-flag-icon" ';
            vuln_flag_html += `data-tooltip-target="tooltip-patched-${idx}" data-tooltip-placement="bottom"><i class="fa-solid fa-shield text-info"></i></span><div id="tooltip-patched-${idx}" role="tooltip" class="tooltip relative z-10 w-80 p-2 text-sm invisible rounded-lg shadow-sm opacity-0 bg-base-300" style="white-space:pre-wrap">This vulnerability was reported (back)patched for the queried version and environment.<div class="tooltip-arrow" data-popper-arrow></div></div>`;
        }

        if (vuln_flag_html)
            vuln_flag_html += '</center>';

        vuln_row_html += vuln_flag_html + "</td>";
    }

    if (selectedColumns.includes('cvss')) {
        var cvss_vector = vuln.cvss_vec;
        if (cvss_vector && !cvss_vector.startsWith('CVSS'))
            cvss_vector = "CVSS:2.0/" + cvss_vector;

        cvss = parseFloat(vuln.cvss);
        if (cvss >= 9.0)
            cvss_badge_css = "badge-critical";
        else if (cvss < 9.0 && cvss >= 7.0)
            cvss_badge_css = "badge-high";
        else if (cvss < 7.0 && cvss >= 4.0)
            cvss_badge_css = "badge-medium";
        else if (cvss < 4.0 && cvss >= 0)
            cvss_badge_css = "badge-low";

        if (cvss_vector && cvss_badge_css)
            vuln_row_html += `<td class="text-nowrap whitespace-nowrap"><div class="dropdown dropdown-hover"><div class="z-10 badge border-none badge-cvss ${cvss_badge_css} text-center ${vuln_style_class} underline decoration-dotted underline-offset-3 cursor-help py-3" tabindex="0">${vuln["cvss"]}&nbsp;(v${vuln["cvss_ver"]})</div><div tabindex="0" class="dropdown-content z-20 menu m-0 p-1 shadow bg-base-300 rounded-box"><div class="btn btn-ghost btn-xs text-smxs" onclick="copyToClipboardCVSS(this)"><span><span><i class="fa-solid fa-clipboard"></i></span>&nbsp;&nbsp;<b>${cvss_vector}</b></span></div></div></div></td>`;
        else
            vuln_row_html += `<td class="text-nowrap whitespace-nowrap text-center"><div class="dropdown dropdown-hover"><div class="z-10 badge p-1.5 border-none badge-cvss badge-na text-center ${vuln_style_class}" tabindex="0">N / A</div><div tabindex="0" class="dropdown-content z-20 menu m-0 p-1 shadow bg-base-300 rounded-box"><div class="btn btn-ghost btn-xs text-smxs" onclick="copyToClipboardCVSS(this)"><span><span><i class="fa-solid fa-clipboard"></i></span>&nbsp;&nbsp;<b>Not Available (N/A)</b></span></div></div></div></td>`;
    }

    if (selectedColumns.includes('epss')) {
        epss = parseFloat(vuln.epss);
        // set custom criticality thresholds
        if (epss >= 0.8)
            epss_badge_css = "badge-critical";
        else if (epss < 0.8 && epss >= 0.5)
            epss_badge_css = "badge-high";
        else if (epss < 0.5 && epss >= 0.2)
            epss_badge_css = "badge-medium";
        else if (epss < 0.2 && epss >= 0)
            epss_badge_css = "badge-low";

        if (epss && epss_badge_css)
            vuln_row_html += `<td class="text-nowrap whitespace-nowrap"><div class="z-10 badge p-1.5 border-none badge-cvss ${epss_badge_css} text-center ${vuln_style_class}" tabindex="0">${vuln["epss"]}</div></td>`;
        else
            vuln_row_html += `<td class="text-nowrap whitespace-nowrap text-center"><div class="z-10 badge p-1.5 border-none badge-cvss badge-na text-center ${vuln_style_class}" tabindex="0">N / A</div></td>`;
    }

    if (selectedColumns.includes('descr')) {
        vuln_row_html += `<td class="text-wrap dont-break-out mx-auto">${htmlEntities(vuln["description"])}</td>`;
    }

    if (selectedColumns.includes('expl')) {
        exploits = [];
        if (vuln.exploits !== undefined) {
            for (var j = 0; j < vuln.exploits.length; j++) {
                if (onlyShowEDBExploits && !vuln.exploits[j].startsWith('https://www.exploit-db.com/exploits/'))
                    continue;

                exploit_url_show = vuln.exploits[j];
                if (exploit_url_show.length > exploit_url_show_max_length) {
                    exploit_url_show = exploit_url_show.substring(0, exploit_url_show_max_length - 2) + '...';
                }
                exploits.push(`<a href="${vuln.exploits[j].replace('"', '&quot;')}" target="_blank" style="color: inherit;">${htmlEntities(exploit_url_show)}</a>`);
            }
        }
        vuln_row_html += `<td class="text-nowrap whitespace-nowrap">${exploits.join("<br>")}</td>`;
    }

    vuln_row_html += "</tr>";
    return vuln_row_html;
}

function renderSearchResults(reloadFilterDropdown) {
    var sortIconVulnId = iconUnsorted, sortFunctionVulnId = "reorderVulns(0, false)";
    var sortIconCVSS = iconUnsorted, sortFunctionCVSS = "reorderVulns(1, false)";
    var sortIconEPSS = iconUnsorted, sortFunctionEPSS = "reorderVulns(2, false)";
    var sortIconExploits = iconUnsorted, sortFunctionExploits = "reorderVulns(4, false)";

    // retrieve and sort vulns
    var vulns = getCurrentVulnsSorted();
    if (curSortColIdx == 0) {  // Vuln ID
        if (curSortColAsc) {
            sortIconVulnId = iconSortAsc;
            sortFunctionVulnId = "reorderVulns(0, false)";
        }
        else {
            sortIconVulnId = iconSortDesc;
            sortFunctionVulnId = "reorderVulns(0, true)";
        }
    }
    else if (curSortColIdx == 1) {  // CVSS
        if (curSortColAsc) {
            sortIconCVSS = iconSortAsc;
            sortFunctionCVSS = "reorderVulns(1, false)";
        }
        else {
            sortIconCVSS = iconSortDesc;
            sortFunctionCVSS = "reorderVulns(1, true)";
        }
    }
    else if (curSortColIdx == 2) {  // EPSS
        if (curSortColAsc) {
            sortIconEPSS = iconSortAsc;
            sortFunctionEPSS = "reorderVulns(2, false)";
        }
        else {
            sortIconEPSS = iconSortDesc;
            sortFunctionEPSS = "reorderVulns(2, true)";
        }
    }
    else if (curSortColIdx == 4) {  // Exploits
        if (curSortColAsc) {
            sortIconExploits = iconSortAsc;
            sortFunctionExploits = "reorderVulns(4, false)";
        }
        else {
            sortIconExploits = iconSortDesc;
            sortFunctionExploits = "reorderVulns(4, true)";
        }
    }

    var selectedColumns = JSON.parse(localStorage.getItem('vulnTableColumns'))
    if (selectedColumns.length < 1) {
        $("#vulns").html('');
        return false;
    }
    
    vulns_html = '<table class="table table-mdsm sv-vuln-table-zebra table-rounded table-auto">';
    vulns_html += '<thead>';
    vulns_html += '<tr>'
    if (selectedColumns.includes('cve')) {
        vulns_html += `<th class="bg-base-300" onclick="${sortFunctionVulnId}" style="white-space: nowrap;">Vuln ID&nbsp;&nbsp;${sortIconVulnId}</th>`;
    }
    if (selectedColumns.includes('cvss')) {
        vulns_html += `<th class="bg-base-300" onclick="${sortFunctionCVSS}" style="white-space: nowrap;">CVSS&nbsp;&nbsp;${sortIconCVSS}</th>`;
    }
    if (selectedColumns.includes('epss')) {
        vulns_html += `<th class="bg-base-300" onclick="${sortFunctionEPSS}" style="white-space: nowrap;">EPSS&nbsp;&nbsp;${sortIconEPSS}</th>`;
    }
    if (selectedColumns.includes('descr')) {
        vulns_html += '<th class="bg-base-300">Description</th>'
    }
    if (selectedColumns.includes('expl')) {
        vulns_html += `<th class="bg-base-300" onclick="${sortFunctionExploits}" style="white-space: nowrap;">Exploits&nbsp;&nbsp;${sortIconExploits}</th>`;
    }
    vulns_html += "</tr></thead>";
    vulns_html += "<tbody>";

    var filter_vulns_html = filterVulnDropdownButtonHtml, has_vulns = false;
    for (var i = 0; i < vulns.length; i++) {
        // create row in table
        if (ignoreGeneralProductVulns && vulns[i].match_reason == "general_product_uncertain")
            continue;
        if (!showSingleVersionVulns && vulns[i].match_reason == "single_higher_version")
            continue;
        if (!showGHSAVulns && vulns[i].id.startsWith('GHSA-'))
            continue;
        if (!showPatchedVulns && vulns[i].reported_patched_by.length > 0)
            continue;

        has_vulns = true;
        var checked_html = "", margin_html = "";
        if (!showTableFiltering || onlyShowTheseVulns == null || onlyShowTheseVulns.includes(vulns[i].id)) {
            vulns_html += createVulnTableRowHtml(i, vulns[i]);
            checked_html = 'checked="checked"';
        }
        if (i != 0)
            margin_html = "mt-3"

        // add Vuln ID to filter
        filter_vulns_html += `<div class="form-control filter-vulns ${margin_html}"><label class="label cursor-pointer flex items-center gap-4 min-w-0 text-sm"><span class="label-text text-nowrap whitespace-nowrap text-base-content flex-1 min-w-0 text-left">${vulns[i]["id"]}</span><input type="checkbox" class="checkbox checkbox-accent rounded-md shrink-0" onclick="changeFilterVulns()" ${checked_html} /></label></div>`;
    }
    vulns_html += "</tbody></table>";
    if (has_vulns)
        $("#vulns").html(vulns_html);

    if (reloadFilterDropdown)
        $('#filterVulnsDropdown').html(filter_vulns_html);  // set Vuln filter HTML
    $('#exportMarkdownIcon').html(exportIcon);
    $('#exportCSVIcon').html(exportIcon);

    initFlowbite();
    fixDropdownClicking();

    return has_vulns;
}

function createVulnsMarkDownTable() {
    var selectedVulns = onlyShowTheseVulns;
    var selectedColumns = JSON.parse(localStorage.getItem('vulnTableColumns'))
    var vulns = getCurrentVulnsSorted(), vuln_id_ref_map;
    var vulns_md = "";
    var has_exploits = false, cur_vuln_has_exploits = false;
    var exploit_url_show;

    for (var i = 0; i < vulns.length; i++) {
        if (selectedVulns != null && selectedVulns.length > 0 && !selectedVulns.includes(vulns[i]["id"]))
            continue;
        if (ignoreGeneralProductVulns && vulns[i].match_reason == "general_product_uncertain")
            continue;
        if (!showSingleVersionVulns && vulns[i].match_reason == "single_higher_version")
            continue;
        if (!showGHSAVulns && vulns[i].id.startsWith('GHSA-'))
            continue;
        if (!showPatchedVulns && vulns[i].reported_patched_by.length > 0)
            continue;

        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0) {
            if (!onlyShowEDBExploits || reduceToEDBUrls(vulns[i].exploits).length > 0) {
                has_exploits = true;
                break
            }
        }
    }

    if (selectedColumns.length > 0) {
        var table_row1 = "|", table_row2 = "|";
        selectedColumns.forEach(column => {
            if (column == 'cve') {
                table_row1 += 'Vuln ID|';
                table_row2 += ':---:|';
            }
            else if (column == 'cvss') {
                table_row1 += 'CVSS|';
                table_row2 += ':---:|';
            }
            else if (column == 'epss') {
                table_row1 += 'EPSS|';
                table_row2 += ':---:|';
            }
            else if (column == 'descr') {
                table_row1 += 'Description|';
                table_row2 += ':---|';
            }
            else if (column == "expl" && has_exploits) {
                table_row1 += 'Exploits|';
                table_row2 += ':---|';
            }
        })
        vulns_md = table_row1 + '\n' + table_row2 + '\n';
    }
    else {
        if (has_exploits) {
            vulns_md = '|Vuln ID|CVSS|Description|Exploits|\n';
            vulns_md += '|:---:|:---:|:---|:---|\n';
        }
        else {
            vulns_md = '|Vuln ID|CVSS|Description|\n';
            vulns_md += '|:---:|:---:|:---|\n';
        }
    }

    for (var i = 0; i < vulns.length; i++) {
        if (selectedVulns != null && selectedVulns.length > 0 && !selectedVulns.includes(vulns[i]["id"]))
            continue;
        if (ignoreGeneralProductVulns && vulns[i].match_reason == "general_product_uncertain")
            continue;
        if (!showSingleVersionVulns && vulns[i].match_reason == "single_higher_version")
            continue;
        if (!showGHSAVulns && vulns[i].id.startsWith('GHSA-'))
            continue;
        if (!showPatchedVulns && vulns[i].reported_patched_by.length > 0)
            continue;

        cur_vuln_has_exploits = false;
        vulns_md += '|';
        if (selectedColumns.length < 1 || selectedColumns.includes("cve")) {
            vuln_id_ref_map = vulns[i].aliases;
            for (const vuln_id in vuln_id_ref_map) {
                if (vuln_id.startsWith('GHSA') && !showGHSAVulns)
                    continue
                vulns_md += `[${vuln_id}](${htmlEntities(vuln_id_ref_map[vuln_id])})<br>`;
            }
            vulns_md = vulns_md.slice(0, -4);  // strip trailing "<br>"
            vulns_md += "|";
        }
        if (selectedColumns.length < 1 || selectedColumns.includes("cvss"))
            vulns_md += `${vulns[i]["cvss"]}&nbsp;(v${vulns[i]["cvss_ver"]})|`;
        if (selectedColumns.length < 1 || selectedColumns.includes("epss"))
            vulns_md += `${vulns[i]["epss"]}|`;
        if (selectedColumns.length < 1 || selectedColumns.includes("descr")) {
            var description = htmlEntities(vulns[i]["description"].trim());
            description = description.replaceAll('\n', '<br>');

            // try to keep markdown for nicer display sometimes
            if (description.includes("**") || description.split("`").length - 1 > 1) {
                description = description.replaceAll('|', '\\|');
            }
            // otherwise escape most impactful Markdown characters.
            // not every Markdown character is escaped, because this
            // creates issues with some parsers.
            else {
                description = escapeMarkdownSimple(description);
            }

            vulns_md += `${description}|`;
        }

        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0 && (selectedColumns.length < 1 || selectedColumns.includes('expl'))) {
            for (var j = 0; j < vulns[i].exploits.length; j++) {
                if (onlyShowEDBExploits && !vulns[i].exploits[j].startsWith('https://www.exploit-db.com/exploits/'))
                    continue;

                exploit_url_show = vulns[i].exploits[j];
                if (exploit_url_show.length > exploit_url_show_max_length_md) {
                    exploit_url_show = exploit_url_show.substring(0, exploit_url_show_max_length_md - 2) + '...';
                }
                vulns_md += `[${htmlEntities(exploit_url_show)}](${vulns[i].exploits[j]})<br>`;
                cur_vuln_has_exploits = true;
            }
            if (cur_vuln_has_exploits) {
                vulns_md = vulns_md.substring(0, vulns_md.length - 4);  // remove last <br>
                vulns_md += "|";
            }
            else if (has_exploits)
                vulns_md += "|";
        }
        else if (has_exploits && (selectedColumns.length < 1 || selectedColumns.includes('expl')))
            vulns_md += "|";

        vulns_md += '\n'
    }

    return vulns_md;
}

function createVulnsCSV() {
    var selectedVulns = onlyShowTheseVulns;
    var selectedColumns = JSON.parse(localStorage.getItem('vulnTableColumns'))
    var vulns = getCurrentVulnsSorted(), vuln_ids;
    var vulns_csv = "", vuln_ids = "";
    var has_exploits = false;

    for (var i = 0; i < vulns.length; i++) {
        if (selectedVulns != null && selectedVulns.length > 0 && !selectedVulns.includes(vulns[i]["id"]))
            continue;
        if (ignoreGeneralProductVulns && vulns[i].match_reason == "general_product_uncertain")
            continue;
        if (!showSingleVersionVulns && vulns[i].match_reason == "single_higher_version")
            continue;
        if (!showGHSAVulns && vulns[i].id.startsWith('GHSA-'))
            continue;
        if (!showPatchedVulns && vulns[i].reported_patched_by.length > 0)
            continue;

        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0) {
            if (!onlyShowEDBExploits || reduceToEDBUrls(vulns[i].exploits).length > 0) {
                has_exploits = true;
                break
            }
        }
    }

    if (selectedColumns.length > 0) {
        selectedColumns.forEach(column => {
            if (column == "cve")
                vulns_csv += 'Vuln ID,';
            else if (column == "cvss")
                vulns_csv += 'CVSS,';
            else if (column == "epss")
                vulns_csv += 'EPSS,';
            else if (column == "descr")
                vulns_csv += 'Description,';
            else if (column == "expl" && has_exploits)
                vulns_csv += 'Exploits,';
        })
        vulns_csv = vulns_csv.slice(0, -1) + '\n';
    }
    else {
        if (has_exploits)
            vulns_csv = 'Vuln ID,CVSS,Description,Exploits\n';
        else
            vulns_csv = 'Vuln ID,CVSS,Description\n';
    }

    for (var i = 0; i < vulns.length; i++) {
        if (selectedVulns != null && selectedVulns.length > 0 && !selectedVulns.includes(vulns[i]["id"]))
            continue;
        if (ignoreGeneralProductVulns && vulns[i].match_reason == "general_product_uncertain")
            continue;
        if (!showSingleVersionVulns && vulns[i].match_reason == "single_higher_version")
            continue;
        if (!showGHSAVulns && vulns[i].id.startsWith('GHSA-'))
            continue;
        if (!showPatchedVulns && vulns[i].reported_patched_by.length > 0)
            continue;

        if (selectedColumns.length < 1 || selectedColumns.includes('cve')) {
            vuln_id_ref_map = vulns[i].aliases;
            vuln_ids = [];
            for (const vuln_id in vuln_id_ref_map) {
                if (vuln_id.startsWith('GHSA') && !showGHSAVulns)
                    continue
                vuln_ids.push(vuln_id);
            }
            if (vuln_ids)
                vulns_csv += `${escapeCSV(vuln_ids.join(', '))}`
            vulns_csv += ','
        }
        if (selectedColumns.length < 1 || selectedColumns.includes('cvss'))
            vulns_csv += `${escapeCSV(vulns[i]["cvss"] + ' (v' + vulns[i]["cvss_ver"] + ')')},`;
        if (selectedColumns.length < 1 || selectedColumns.includes('cvss'))
            vulns_csv += `${escapeCSV(vulns[i]["epss"])},`;
        if (selectedColumns.length < 1 || selectedColumns.includes('descr'))
            vulns_csv += `${escapeCSV(vulns[i]["description"].trim())},`;

        if (vulns_csv.length > 0 && (!has_exploits || (selectedColumns.length > 0 && !selectedColumns.includes('expl'))))
            vulns_csv = vulns_csv.slice(0, -1);

        if (has_exploits && vulns[i].exploits !== undefined && vulns[i].exploits.length > 0 && (selectedColumns.length < 1 || selectedColumns.includes('expl'))) {
            if (onlyShowEDBExploits)
                vulns_csv += `${escapeCSV(reduceToEDBUrls(vulns[i].exploits).join(", "))}`;
            else
                vulns_csv += `${escapeCSV(vulns[i].exploits.join(", "))}`;
        }
        vulns_csv += '\n'
    }

    return vulns_csv;
}


function buildTextualReprFromCPE(cpe) {
    var product_title, cpe_parts, product_type, cpe_condition = '';
    cpe_parts = cpe.split(":");
    cpe_condition = '';

    if (cpe_parts[2] == 'a')
        product_type = 'Software';
    else if (cpe_parts[2] == 'o')
        product_type = 'Operating System';
    else if (cpe_parts[2] == 'h')
        product_type = 'Hardware';

    cpe_parts[3] = cpe_parts[3][0].toUpperCase() + cpe_parts[3].substring(1);
    cpe_parts[4] = cpe_parts[4][0].toUpperCase() + cpe_parts[4].substring(1);
    if (cpe_parts[4].startsWith(cpe_parts[3]))
        cpe_parts[4] = cpe_parts[4].substring(cpe_parts[3].length).trim();
    if (cpe_parts[4].startsWith('_'))
        cpe_parts[4] = cpe_parts[4].substring(1);

    product_title = cpe_parts[3].split('_').map(w => w[0].toUpperCase() + w.substring(1).toLowerCase()).join(' ') + ' ';
    if (cpe_parts[4] && cpe_parts[4] != cpe_parts[3]) {
        var append_words = cpe_parts[4].split('_').map(w => w[0].toUpperCase() + w.substring(1).toLowerCase()).join(' ') + ' ';
        append_words = append_words.replace(/^[\W_]+/, '');
        append_words = append_words.charAt(0).toUpperCase() + append_words.slice(1);
        product_title += append_words;
    }

    if (cpe_parts[5] && cpe_parts[5] != '-' && cpe_parts[5] != '*')
        product_title += cpe_parts[5] + ' ';

    if (cpe_parts[6] && cpe_parts[6] != '-' && cpe_parts[6] != '*')
        product_title += cpe_parts[6] + ' ';

    cpe_parts.slice(7).forEach(cpe_part => {
        if (cpe_part && cpe_part != '-' && cpe_part != '*') {
            var cpe_part = cpe_part[0].toUpperCase() + cpe_part.substring(1);
            cpe_condition += cpe_part.split('_').map(w => w ? w[0].toUpperCase() + w.substring(1).toLowerCase(): '').join(' ') + ' ';
        }
    });

    product_title = product_title.trim();
    cpe_condition = cpe_condition.trim();

    if (cpe_condition)
        return product_type + ': ' + product_title + ' ' + '[' + cpe_condition + ']';

    return product_type + ': ' + product_title
}


function searchVulns(query, url_query, recaptcha_response) {
    var headers = {}
    if (recaptcha_response !== undefined)
        headers = {'Recaptcha-Response': recaptcha_response}

    var apiKey = localStorage.getItem('apiKey');
    if (apiKey !== undefined && apiKey !== null && apiKey)
        headers['API-Key'] = apiKey

    $.get({
        url: "/api/search-vulns",
        headers: headers,
        data: url_query,
        success: function (search_results) {
            var search_display_html = "", related_queries_html = '', queryError = false;
            var productIDs = search_results.product_ids;
            productIDs = Object.values(productIDs).flatMap(pids => pids);

            if (typeof Object.values(search_results)[0] !== "object") {
                search_display_html = `<h5 class="text-error text-center">Warning: Could not find matching software for query '${htmlEntities(query)}'</h5>`;
                queryError = true;
            }
            else {
                if ((productIDs != undefined && productIDs.length != 0) || Object.keys(search_results.vulns).length != 0) {
                    curVulnData = search_results.vulns;
                    search_display_html = `<div class="row mt-2"><div class="col text-center text-info"><h5 style="font-size: 1.05rem;">${htmlEntities(query)}`;
                    if (productIDs.length > 0 && productIDs[0].length > 0)  // show product ID (when searching for just vuln IDs there is none)
                        search_display_html += `<span class="nowrap whitespace-nowrap"> (${htmlEntities(productIDs[0])}`;
                    if (productIDs.length > 1) {  // query has equivalent product IDs
                        search_display_html += '<div class="dropdown dropdown-hover dropdown-bottom dropdown-end ml-2"><div class="btn btn-circle btn-outline btn-info btn-xxs"><i class="fa-solid fa-up-right-and-down-left-from-center"></i></div><div class="dropdown-content translate-x-2.5 z-[1] p-3 shadow bg-base-300 rounded-box text-base-content w-fit" onclick="document.activeElement.blur();"><h5 class="font-medium text-left text-sm">Equivalent product IDs that were included into your search: <div class="tooltip tooltip-top text-wrap ml-1" data-tip="Sometimes there are multiple IDs for one product, e.g. because of a rebranding."><i class="fas fa-info-circle text-content"></i></div></h5><ul tabindex="0" class="list-disc pl-6 mt-1 text-left text-sm font-light">';
                        productIDs.shift();  // remove first element, i.e. the primarily matched product ID
                        productIDs = productIDs.sort();
                        productIDs.forEach(function (curProductID) {
                            search_display_html += `<li class="mt-1">${htmlEntities(curProductID)}</li>`;
                        });
                        search_display_html += '</ul></div></div>';
                    }
                    if (productIDs.length > 0 && productIDs[0].length > 0)  // if a product ID was shown, add closing parenthesis and <span>
                        search_display_html += `)</span>`;
                    search_display_html += `</h5></div></div>`;
                    curEOLData = {'query': query, 'version_status': search_results.version_status};
                    if (search_results.version_status) {
                        if (search_results.version_status.status == 'eol') {
                            search_display_html += `<div class="row mt-1 mb-3 text-warning text-smxs font-light">${htmlEntities(query)} is end of life. The latest version is ${htmlEntities(search_results.version_status.latest)} (see <a class="link" target="_blank" href="${htmlEntities(search_results.version_status.ref)}">here</a>).<span class="ml-2 text-base-content"><button class="btn btn-sm btn-copy-md align-middle" onclick="copyToClipboardEOLProof(this)"><i class="fa-brands fa-markdown"></i></button></span></div>`;
                        }
                        else if (search_results.version_status.status == 'outdated') {
                            search_display_html += `<div class="row mt-1 mb-3 text-warning text-smxs font-light">${htmlEntities(query)} is out of date. The latest version is ${htmlEntities(search_results.version_status.latest)} (see <a class="link" target="_blank" href="${htmlEntities(search_results.version_status.ref)}">here</a>).<span class="ml-2 text-base-content"><button class="btn btn-sm btn-copy-md align-middle" onclick="copyToClipboardEOLProof(this)"><i class="fa-brands fa-markdown"></i></button></span></div>`;
                        }
                        else if (search_results.version_status.status == 'current') {
                            search_display_html += `<div class="row mt-1 mb-3 text-success text-smxs font-light">${htmlEntities(query)} is up to date (see <a class="link" target="_blank" href="${htmlEntities(search_results.version_status.ref)}">here</a>).<span class="ml-2 text-base-content"><button class="btn btn-sm btn-copy-md align-middle"><i class="fa-brands fa-markdown" onclick="copyToClipboardEOLProof(this)"></i></button></span></div>`;
                        }
                        else if (search_results.version_status.status == 'N/A') {
                            search_display_html += `<div class="row mt-1 mb-3 text-base-content text-smxs font-light">The latest version of ${htmlEntities(query)} is ${htmlEntities(search_results.version_status.latest)} (see <a class="link" target="_blank" href="${htmlEntities(search_results.version_status.ref)}">here</a>).<span class="ml-2 text-base-content"><button class="btn btn-sm btn-copy-md align-middle" onclick="copyToClipboardEOLProof(this)"><i class="fa-brands fa-markdown"></i></button></span></div>`;
                        }
                    }
                }
                else {
                    search_display_html = `<h5 class="text-error w-full text-center">Warning: Could not find matching software for query '${htmlEntities(query)}'</h5>`;
                    queryError = true;
                }

                if (search_results.hasOwnProperty('pot_product_ids')) {
                    var allProductIDs = formatProductIDSuggestions(search_results.pot_product_ids);
                    if (allProductIDs.length != 0) {
                        var related_queries_html_li = "";
                        for (var i = 0; i < allProductIDs.length; i++) {
                            if (productIDs == null || !productIDs.includes(allProductIDs[i]))
                                related_queries_html_li += `<li><a href="${window.location.pathname}?query=${encodeURIComponent(htmlEntities(allProductIDs[i]))}&is-good-product-id=false">${htmlEntities(allProductIDs[i])} &nbsp; &nbsp;(${htmlEntities(buildTextualReprFromCPE(allProductIDs[i]))})</a></li>`
                        }

                        if (related_queries_html_li != "") {
                            related_queries_html = `<div class="divider divider-info text-lg">Related Queries</div>`;
                            related_queries_html += `<div class="grid place-items-center">`;
                            related_queries_html += `<ul class="list-disc text-left pl-6">`;
                            related_queries_html += related_queries_html_li;
                            related_queries_html += `</ul></div>`;
                        }
                    }
                }
            }

            $("#search-display").html(search_display_html);
            onlyShowTheseVulns = null;
            var hasVulns = renderSearchResults(true);
            if (!hasVulns && !queryError)
                $('#vulns').html(noVulnsFoundHtml);
                
            $("#related-queries-display").html(related_queries_html);
            $("#buttonSearchVulns").removeClass("btn-disabled");
            $("#buttonFilterVulns").removeClass("btn-disabled");
            $("#buttonManageColumns").removeClass("btn-disabled");
            $("#buttonExportResults").removeClass("btn-disabled");
            $("#buttonSearchVulns").html('<i class="fa-solid fa-magnifying-glass"></i><span class="max-md:hidden">Search Vulns</span>');
            currentlySearchingVulns = false;
        },
        error: function (jXHR, textStatus, errorThrown) {
            var errorMsg;
            if ("responseText" in jXHR)
                errorMsg = jXHR["responseText"];
            else
                errorMsg = errorThrown;
            errorMsg = htmlEntities(errorMsg);

            if (jXHR["status"] == 403 && errorMsg.toLowerCase().includes("captcha")) {
                errorMsg += ' Set up a key <a class="link" href="/api/setup">here<a>.';
            }

            $("#vulns").html(`<h5 class="text-error w-full text-center">${errorMsg}</h5>`);

            $("#buttonSearchVulns").removeClass("btn-disabled");
            $("#buttonFilterVulns").removeClass("btn-disabled");
            $("#buttonManageColumns").removeClass("btn-disabled");
            $("#buttonExportResults").removeClass("btn-disabled");
            $("#buttonSearchVulns").html('<i class="fa-solid fa-magnifying-glass"></i> Search Vulns');
            currentlySearchingVulns = false;
        }
    });
}

function searchVulnsAction(actionElement) {
    clearTimeout(doneTypingQueryTimer);

    var query = $('#query').val(), queryEnc;
    if (query === undefined)
        query = '';

    if (actionElement.id.startsWith('product-id-suggestion')) {
        queryEnc = encodeURIComponent($(actionElement).html());
        isGoodProductID = false;
    }
    else {
        queryEnc = encodeURIComponent(query);
    }

    url_query = "query=" + queryEnc;
    new_url = window.location.pathname + '?query=' + queryEnc;

    if (!isGoodProductID) {
        url_query += "&is-good-product-id=false";
        new_url += '&is-good-product-id=false';
    }

    // false is default in backend and filtering is done in frontend
    url_query += "&include-single-version-vulns=true";
    url_query += "&include-patched=true";

    isGoodProductID = true;  // reset for subsequent query that wasn't initiated via URL

    history.pushState({}, null, new_url);  // update URL
    $("#buttonSearchVulns").html('<span class="loading loading-spinner"></span><span class="max-md:hidden">Searching</span>');
    $("#buttonSearchVulns").addClass("btn-disabled");
    $("#buttonFilterVulns").addClass("btn-disabled");
    $("#buttonManageColumns").addClass("btn-disabled");
    $("#buttonExportResults").addClass("btn-disabled");
    $('#productIDSuggestions').addClass("hidden");
    $('#productIDSuggestions').html();
    curSelectedProductIDSuggestion = -1;
    searchIgnoreNextKeyup = true;

    $("#search-display").html("");
    $("#related-queries-display").html("");
    $("#vulns").html('<div class="row mt-3 justify-content-center align-items-center"><h5 class="spinner-border text-primary" style="width: 3rem; height: 3rem"></h5></div>');
    curSortColIdx = 1;
    curSortColAsc = false;
    curVulnData = {};
    curEOLData = {};

    if (typeof grecaptcha !== 'undefined') {
        grecaptcha.ready(function() {
            grecaptcha.execute().then(function(recaptcha_response) {
                searchVulns(query, url_query, recaptcha_response);
            });
        });
    }
    else {
        searchVulns(query, url_query);
    }
}

function reorderVulns(sortColumnIdx, asc) {
    curSortColIdx = sortColumnIdx;
    curSortColAsc = asc;
    var hasVulns = renderSearchResults(true);
    if (!hasVulns)
        $('#vulns').html(noVulnsFoundHtml);
}

function copyToClipboardEOLProof(clickedButton) {
    // copy Markdown proof to clipboard depending on version status
    var markdownProof = '';
    if (curEOLData.version_status) {
        if (curEOLData.version_status.status == 'eol') {
            markdownProof = `${htmlEntities(curEOLData.query)} is end of life. The latest version is ${htmlEntities(curEOLData.version_status.latest)} (see [here](${htmlEntities(curEOLData.version_status.ref)})).`;
        }
        else if (curEOLData.version_status.status == 'outdated') {
            markdownProof = `${htmlEntities(curEOLData.query)} is out of date. The latest version is ${htmlEntities(curEOLData.version_status.latest)} (see [here](${htmlEntities(curEOLData.version_status.ref)})).`;
        }
        else if (curEOLData.version_status.status == 'current') {
            markdownProof = `${htmlEntities(curEOLData.query)} is up to date (see [here](${htmlEntities(curEOLData.version_status.ref)})).`;
        }
        else if (curEOLData.version_status.status == 'N/A') {
            markdownProof = `The latest version of ${htmlEntities(curEOLData.query)} is ${htmlEntities(curEOLData.version_status.latest)} (see [here](${htmlEntities(curEOLData.version_status.ref)})).`;
        }
    }
    navigator.clipboard.writeText(markdownProof);

    // indicate success
    $(clickedButton).removeClass('text-base-content');
    $(clickedButton).addClass('text-success');
    setTimeout(function() {
        $(clickedButton).removeClass('text-success');
        $(clickedButton).addClass('text-base-content');
    }, 1750);
}

function copyToClipboardMarkdownTable() {
    navigator.clipboard.writeText(createVulnsMarkDownTable());
    $('#exportMarkdownIcon').html(exportIconSuccess);
}

function copyToClipboardCSV() {
    navigator.clipboard.writeText(createVulnsCSV());
    $('#exportCSVIcon').html(exportIconSuccess);
}

function copyToClipboardCVSS(cvssClipboardButton) {
    navigator.clipboard.writeText($(cvssClipboardButton).find("b").text());
    $(cvssClipboardButton).find('span').find('span').addClass('text-success');
    $(cvssClipboardButton).find('span').find('span').html('<i class="fa-solid fa-clipboard-check"></i>');
    document.activeElement.blur();
}

function changeSearchConfig(configElement) {
    var settingEnabled = false, settingEnabledStr = "false";
    if (configElement.checked) {
        settingEnabled = true;
        settingEnabledStr = "true";
    }

    if (configElement.id == "generalVulnsConfig") {
        ignoreGeneralProductVulns = settingEnabled;
        localStorage.setItem("ignoreGeneralProductVulns", settingEnabledStr);
    }
    else if (configElement.id == "onlyEdbExploitsConfig") {
        onlyShowEDBExploits = settingEnabled;
        localStorage.setItem("onlyShowEDBExploits", settingEnabledStr);
    }
    else if (configElement.id == "showSingleVersionVulnsConfig") {
        showSingleVersionVulns = settingEnabled;
        localStorage.setItem("showSingleVersionVulns", settingEnabledStr);
    }
    else if (configElement.id == "showGHSAVulnsConfig") {
        showGHSAVulns = settingEnabled;
        localStorage.setItem("showGHSAVulns", settingEnabledStr);
    }
    else if (configElement.id == "showPatchedVulnsConfig") {
        showPatchedVulns = settingEnabled;
        localStorage.setItem("showPatchedVulns", settingEnabledStr);
    }
    else if (configElement.id == "showTableFilteringConfig") {
        showTableFiltering = settingEnabled;
        localStorage.setItem("showTableFiltering", settingEnabledStr);
    }

    if (!$.isEmptyObject(curVulnData)) {
        var hasVulns = renderSearchResults(true);
        if (!hasVulns)
            $('#vulns').html(noVulnsFoundHtml);
    }
}

function changeColumnConfig(columnElement) {
    var vulnTableColumns = [], allCheckType = null;

    if (columnElement.id == 'showColumnAll')
        allCheckType = true
    else if (columnElement.id == 'showColumnNone')
        allCheckType = false

    if (allCheckType != null) {
        columnCheckboxIDs = ['showColumnVulnId', 'showColumnCVSS', 'showColumnEPSS', 'showColumnDescription', 'showColumnExploits'];
        columnCheckboxIDs.forEach(function(columnCheckboxID) {
            $('#' + columnCheckboxID)[0].checked = allCheckType;
        });
    }

    if ($('#showColumnVulnId')[0].checked)
        vulnTableColumns.push('cve');
    if ($('#showColumnCVSS')[0].checked)
        vulnTableColumns.push('cvss');
    if ($('#showColumnEPSS')[0].checked)
        vulnTableColumns.push('epss');
    if ($('#showColumnDescription')[0].checked)
        vulnTableColumns.push('descr');
    if ($('#showColumnExploits')[0].checked)
        vulnTableColumns.push('expl');

    localStorage.setItem('vulnTableColumns', JSON.stringify(vulnTableColumns));

    if (!$.isEmptyObject(curVulnData) && showTableFiltering)
        renderSearchResults();
}

function changeFilterVulns(filterVulnsButton) {
    onlyShowTheseVulns = [];
    var allOrNone = '';

    if (filterVulnsButton != null) {
        if(filterVulnsButton.id == 'filterVulnsNone')
            allOrNone = 'none';
        else {
            onlyShowTheseVulns = null;
            allOrNone = 'all';
        }
    }

    $('.filter-vulns').each(function(i, filterVulnsDiv) {
        filterVulnsDiv = $(filterVulnsDiv);
        if (allOrNone == 'none')
            filterVulnsDiv.find('.checkbox')[0].checked = false;
        else if (allOrNone == 'all')
            filterVulnsDiv.find('.checkbox')[0].checked = true;

        if (onlyShowTheseVulns != null && filterVulnsDiv.find('.checkbox')[0].checked)
            onlyShowTheseVulns.push(filterVulnsDiv.find('.label-text').text().trim());
    });

    if (!$.isEmptyObject(curVulnData) && showTableFiltering)
        renderSearchResults();
}

function setupConfigFromLocalstorage() {
    if (localStorage.getItem('ignoreGeneralProductVulns') === null) {
        localStorage.setItem('ignoreGeneralProductVulns', 'false');
    }
    if (localStorage.getItem('onlyShowEDBExploits') === null) {
        localStorage.setItem('onlyShowEDBExploits', 'false');
    }
    if (localStorage.getItem('showSingleVersionVulns') === null) {
        localStorage.setItem('showSingleVersionVulns', 'false');
    }
    if (localStorage.getItem('showGHSAVulns') === null) {
        localStorage.setItem('showGHSAVulns', 'true');
    }
    if (localStorage.getItem('showPatchedVulns') === null) {
        localStorage.setItem('showPatchedVulns', 'true');
    }
    if (localStorage.getItem('showTableFiltering') === null) {
        localStorage.setItem('showTableFiltering', 'true');
    }
    
    if (localStorage.getItem('ignoreGeneralProductVulns') == 'true') {
        ignoreGeneralProductVulns = true;
        document.getElementById("generalVulnsConfig").checked = true;
    }
    if (localStorage.getItem('onlyShowEDBExploits') == 'true') {
        onlyShowEDBExploits = true;
        document.getElementById("onlyEdbExploitsConfig").checked = true;
    }
    if (localStorage.getItem('showSingleVersionVulns') == 'true') {
        showSingleVersionVulns = true;
        document.getElementById("showSingleVersionVulnsConfig").checked = true;
    }
    if (localStorage.getItem('showGHSAVulns') == 'true') {
        showGHSAVulns = true;
        document.getElementById("showGHSAVulnsConfig").checked = true;
    }
    if (localStorage.getItem('showPatchedVulns') == 'true') {
        showPatchedVulns = true;
        document.getElementById("showPatchedVulnsConfig").checked = true;
    }
    if (localStorage.getItem('showTableFiltering') == 'true') {
        showTableFiltering = true;
        document.getElementById("showTableFilteringConfig").checked = true;
    }
    
    if (localStorage.getItem('vulnTableColumns') === null) {
        localStorage.setItem('vulnTableColumns', '["cve", "cvss", "descr", "expl"]');
    }
    var vulnTableColumns = JSON.parse(localStorage.getItem('vulnTableColumns'))

    if (vulnTableColumns.includes('cve'))
        document.getElementById("showColumnVulnId").checked = true;
    if (vulnTableColumns.includes('cvss'))
        document.getElementById("showColumnCVSS").checked = true;
    if (vulnTableColumns.includes('epss'))
        document.getElementById("showColumnEPSS").checked = true;
    if (vulnTableColumns.includes('descr'))
        document.getElementById("showColumnDescription").checked = true;
    if (vulnTableColumns.includes('expl'))
        document.getElementById("showColumnExploits").checked = true;
}

function initQuery() {
    if (location.search !== '' && location.search !== '?') {
        var url = new URL(document.location.href);
        var params = new URLSearchParams(url.search);
        var init_query = params.get('query');
        if (init_query !== null)
            $('#query').val(htmlEntities(init_query));

        var is_good_product_id = params.get('is-good-product-id');
        if (String(is_good_product_id).toLowerCase() === "false")
            isGoodProductID = false;

        if (init_query !== null)
            $("#buttonSearchVulns").click();
    }
}

function fixDropdownClicking() {
    $('.dropdown').find('.btn:first').on('mousedown', function(event) {
        var closestDropdown = document.activeElement.closest('.dropdown') 
        if (closestDropdown !== null && closestDropdown == event.target.closest('.dropdown')) {
            event.preventDefault();
            document.activeElement.blur();
        }
    });
}

function formatProductIDSuggestions(productIDInfos) {
    var allProductIDs = [];

    // flatten dict into list of product IDs
    for (const productIDType in productIDInfos) {
        for (const [productID, score] of productIDInfos[productIDType]) {
            allProductIDs.push([productID, score]);
        }
    }

    // sort list of product IDs with score by score (keep created IDs atop, which is marked by negative score)
    allProductIDs.sort((p1, p2) => {
        const absP1 = Math.abs(p1[1]);
        const absP2 = Math.abs(p2[1]);

        if (absP1 !== absP2) {
            return absP2 - absP1;
        } else {
            return p1[1] - p2[1]; // negative comes before positive if equal
        }
    });

    // remap list to only the product IDs
    return allProductIDs.map(([str]) => str);
}

function retrieveProductIDSuggestions(url_query, recaptcha_response) {
    var headers = {}
    if (recaptcha_response !== undefined)
        headers['Recaptcha-Response'] = recaptcha_response

    var apiKey = localStorage.getItem('apiKey');
    if (apiKey !== undefined && apiKey !== null && apiKey)
        headers['API-Key'] = apiKey

    $.get({
        url: "/api/product-id-suggestions",
        data: url_query,
        headers: headers,
        success: function (productIDInfos) {
            if (productIDInfos === null || typeof productIDInfos !== 'object' || Array.isArray(productIDInfos)) {
                console.log(productIDInfos)
                $('#productIDSuggestions').html('<span class="text-error">An error occured, see console</span>');
            }
            else {
                var allProductIDs = formatProductIDSuggestions(productIDInfos);
                if (allProductIDs.length != 0) {
                    var dropdownContent = '<ul class="menu menu-md p-1 bg-base-200 rounded-box w-full">';
                    for (var i = 0; i < allProductIDs.length; i++) {
                        dropdownContent += `<li tabindex="0"><a class="text-nowrap whitespace-nowrap" id="product-id-suggestion-${i}" onclick="searchVulnsAction(this)">${htmlEntities(allProductIDs[i])}</a></li>`;
                    }
                    dropdownContent += '</ul>';
                    $('#productIDSuggestions').html(dropdownContent);
                }
                else {
                    $('#productIDSuggestions').html("No possible product IDs found");
                }
            }
            curSelectedProductIDSuggestion = -1
            suggestedQueriesJustOpened = true;
            setTimeout(function () {
                suggestedQueriesJustOpened = false;
            }, 400);
            $("#buttonSearchVulns").removeClass("btn-disabled");
        },
        error: function (jXHR, textStatus, errorThrown) {
            var errorMsg;
            if ("responseText" in jXHR)
                errorMsg = jXHR["responseText"];
            else
                errorMsg = errorThrown;

            console.log(errorMsg);

            if (jXHR["status"] == 403 && errorMsg.toLowerCase().includes("captcha")) {
                    $('#productIDSuggestions').html('<span class="text-error">No valid API key / CAPTCHA provided. Set up a key <a class="link" onmousedown="location.href = \'/api/setup\'">here<a>.');
            }
            else {
                $('#productIDSuggestions').html('<span class="text-error">' + htmlEntities(errorMsg) + '</span>');
            }

            $("#buttonSearchVulns").removeClass("btn-disabled");
        }
    });
}

function doneTypingQuery () {
    // user paused or finished typing query --> retrieve and show product ID suggestions
    $('#productIDSuggestions').html('<div class="loading loading-spinner"></div>');
    $('#productIDSuggestions').removeClass('hidden');
    $("#buttonSearchVulns").addClass("btn-disabled");

    var query = $('#query').val();
    if (query === undefined)
        query = '';

    // no product ID suggestions for vuln IDs search
    if (query.trim().startsWith('CVE') || query.trim().startsWith('GHSA')){
        $('#productIDSuggestions').html('');
        $("#buttonSearchVulns").removeClass("btn-disabled");
        return;
    }

    var queryEnc = encodeURIComponent(query);
    var url_query = "query=" + queryEnc;

    if (typeof grecaptcha !== 'undefined') {
        grecaptcha.ready(function() {
            grecaptcha.execute().then(function(recaptcha_response) {
                retrieveProductIDSuggestions(url_query, recaptcha_response);
            });
        });
    }
    else {
        retrieveProductIDSuggestions(url_query);
    }
}

function closeProductIDSuggestions(event) {
    // Check that new focused element lies without the queryInputConstruct / dropdown
    var newFocusedElement = event.relatedTarget;
    if (newFocusedElement === null || newFocusedElement.closest('#queryInputConstruct') === null) {
        $('#productIDSuggestions').addClass('hidden');
    }
}

function ensureSuggestionVisible(suggestionElement) {
    const dropdownMenu = $('#productIDSuggestions')[0];
    const suggestionElementRect = suggestionElement.getBoundingClientRect();
    const dropdownRect = dropdownMenu.getBoundingClientRect();

    if (suggestionElementRect.top < dropdownRect.top) {
        dropdownMenu.scrollTop -= (dropdownRect.top - suggestionElementRect.top);
    } else if (suggestionElementRect.bottom > dropdownRect.bottom) {
        dropdownMenu.scrollTop += (suggestionElementRect.bottom - dropdownRect.bottom);
    }
}


/* init */

// enables the user to press return on the query text field to make the query
$("#query").keypress(function (event) {
    var keycode = (event.keyCode ? event.keyCode : event.which);
    if (keycode == "13") {
        if (!$("#productIDSuggestions").hasClass("hidden") || !$("#buttonSearchVulns").hasClass("btn-disabled")) {
            var highlightedProductIDSuggestion = null;
            if ($("#productIDSuggestions").find('ul') != null) {
                highlightedProductIDSuggestion = $("#productIDSuggestions").find('.my-menu-item-hover');
            }
            if (!highlightedProductIDSuggestion || curSelectedProductIDSuggestion == -1)
                $("#buttonSearchVulns").click();
            else
                document.getElementById('product-id-suggestion-' + curSelectedProductIDSuggestion).click();
        }
    }
});

function moveProductIDSuggestionUpDown(event) {
    // move currently selected product ID suggestion up or down depending on event
    if (curSelectedProductIDSuggestion > -1)
        $('#product-id-suggestion-' + curSelectedProductIDSuggestion).removeClass('my-menu-item-hover');

    console.log(curSelectedProductIDSuggestion);
    if (event.keyCode == 38)
        curSelectedProductIDSuggestion--;
    else if (event.keyCode == 40)
        curSelectedProductIDSuggestion++;

    // wrap around if moving below available suggestions or above them
    if (curSelectedProductIDSuggestion < -1)
        curSelectedProductIDSuggestion = $("#productIDSuggestions").find('ul').children('li').length - 1;
    else if (curSelectedProductIDSuggestion > $("#productIDSuggestions").find('ul').children('li').length - 1)
        curSelectedProductIDSuggestion = -1;

    if (curSelectedProductIDSuggestion > -1) {
        const suggestionElement = $('#product-id-suggestion-' + curSelectedProductIDSuggestion);
        suggestionElement.addClass('my-menu-item-hover');
        ensureSuggestionVisible(suggestionElement[0]);
    }
}


// check for API key
if (localStorage.getItem('apiKey') !== null)
    document.cookie = 'isAPIKeyConfigured=true; secure; path=/';

// fix dropdown open buttons to close again on click
fixDropdownClicking();

// setup configuration from LocalStorage
setupConfigFromLocalstorage();

// check for existing query in URL and insert its parameters
initQuery();

// register timers and functions for query input field
// on keyup, start the countdown to register finished typing
queryInput.on('keyup', function (event) {
    if (event.keyCode !== undefined) {
        // arrows (up: 38 ; down: 40)
        if ([38, 40].includes(event.keyCode) && !$('#productIDSuggestions').hasClass('hidden') && $("#productIDSuggestions").find('ul') != null) {
            if (arrowKeyUpDownInterval !== null) {
                clearInterval(arrowKeyUpDownInterval);
                arrowKeyUpDownInterval = null;
            }
            if (arrowKeyUpDownHoldDetectionTimer !== null) {
                clearTimeout(arrowKeyUpDownHoldDetectionTimer);
                arrowKeyUpDownHoldDetectionTimer = null;
            }
            event.preventDefault();  // prevent jumping of cursor to start or end
        }
        // any key except CTRL, OPTION, CMD/SUPER/Windows
        else if (![13, 17, 18, 91, 229].includes(event.keyCode)) {
            clearTimeout(doneTypingQueryTimer);
            if (!searchIgnoreNextKeyup)
                doneTypingQueryTimer = setTimeout(doneTypingQuery, doneTypingQueryInterval);
            searchIgnoreNextKeyup = false;
        }
    }
});

// on keydown, clear the typing countdown and hide dropdown
queryInput.on('keydown', function (event) {
    if (event.keyCode !== undefined) {
        if ([38, 40].includes(event.keyCode) && !$('#productIDSuggestions').hasClass('hidden') && $("#productIDSuggestions").find('ul') != null) {
            event.preventDefault();  // prevent jumping of cursor to start or end

            // register key press only if no interval is running or about to run
            if (arrowKeyUpDownInterval === null && arrowKeyUpDownHoldDetectionTimer == null) {
                // immediately trigger once
                moveProductIDSuggestionUpDown(event);

                // set a timer to detect held down key and initiate a repeated interval
                arrowKeyUpDownHoldDetectionTimer = setTimeout(() => {
                    arrowKeyUpDownInterval = setInterval(() => {
                        moveProductIDSuggestionUpDown(event);
                    }, arrowKeyUpDownIntervalTime);
                }, arrowKeyUpDownHoldDetectionTime);
            }
        }
        // any key except CTRL, OPTION, CMD/SUPER/Windows
        else if(![13, 17, 18, 37, 39, 91, 229].includes(event.keyCode)) {
            clearTimeout(doneTypingQueryTimer);
            $('#productIDSuggestions').addClass("hidden");
            $('#productIDSuggestions').html();
        }
    }
});

// focus on query input field at the beginning
window.onload = function () {
    queryInput.focus();
}
