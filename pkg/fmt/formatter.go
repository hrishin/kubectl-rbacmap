package fmt

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/hrishis/kubectl-rbacmap/pkg/rbac"
)

var headers = [4]string{"RESOURCE", "ACTIONS", "ROLE", "BINDING"}

// PrintSubjectPermissions writes the formatted permissions for all subjects
// to the given writer. Supported formats: "table" (default), "markdown", "csv".
func PrintSubjectPermissions(w io.Writer, results []rbac.SubjectPermissions, format string) {
	switch strings.ToLower(format) {
	case "csv":
		printCSV(w, results)
	case "markdown", "md":
		printMarkdown(w, results)
	default:
		printTable(w, results)
	}
}

// printTable renders output using kubectl-style tabwriter columns.
func printTable(w io.Writer, results []rbac.SubjectPermissions) {
	for i, sp := range results {
		if i > 0 {
			fmt.Fprintln(w)
		}

		printSubjectHeader(w, sp.Subject)

		if len(sp.Permissions) == 0 {
			fmt.Fprintln(w, "(no permissions found)")
			continue
		}

		grouped := groupByResource(sp.Permissions)

		tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", headers[0], headers[1], headers[2], headers[3])
		for _, entry := range grouped {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
				entry.Resource, entry.Actions, entry.RoleRef, entry.BindingRef)
		}
		tw.Flush()
	}
}

// printMarkdown renders output as a markdown-style table.
func printMarkdown(w io.Writer, results []rbac.SubjectPermissions) {
	for i, sp := range results {
		if i > 0 {
			fmt.Fprintln(w)
		}

		printSubjectHeader(w, sp.Subject)

		if len(sp.Permissions) == 0 {
			fmt.Fprintln(w, "(no permissions found)")
			continue
		}

		grouped := groupByResource(sp.Permissions)

		// Compute max column widths
		widths := [4]int{len(headers[0]), len(headers[1]), len(headers[2]), len(headers[3])}
		for _, entry := range grouped {
			cols := [4]string{entry.Resource, entry.Actions, entry.RoleRef, entry.BindingRef}
			for j, col := range cols {
				if len(col) > widths[j] {
					widths[j] = len(col)
				}
			}
		}

		// Header row
		fmt.Fprintf(w, "| %-*s | %-*s | %-*s | %-*s |\n",
			widths[0], headers[0], widths[1], headers[1],
			widths[2], headers[2], widths[3], headers[3])

		// Separator row
		fmt.Fprintf(w, "|-%s-|-%s-|-%s-|-%s-|\n",
			strings.Repeat("-", widths[0]), strings.Repeat("-", widths[1]),
			strings.Repeat("-", widths[2]), strings.Repeat("-", widths[3]))

		// Data rows
		for _, entry := range grouped {
			fmt.Fprintf(w, "| %-*s | %-*s | %-*s | %-*s |\n",
				widths[0], entry.Resource, widths[1], entry.Actions,
				widths[2], entry.RoleRef, widths[3], entry.BindingRef)
		}
	}
}

// printCSV renders output in CSV format.
func printCSV(w io.Writer, results []rbac.SubjectPermissions) {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Write header
	cw.Write([]string{"SUBJECT KIND", "SUBJECT NAME", headers[0], headers[1], headers[2], headers[3]})

	for _, sp := range results {
		kindLabel := subjectKindLabel(sp.Subject)

		if len(sp.Permissions) == 0 {
			cw.Write([]string{kindLabel, sp.Subject.Name, "(no permissions found)", "", "", ""})
			continue
		}

		grouped := groupByResource(sp.Permissions)
		for _, entry := range grouped {
			cw.Write([]string{
				kindLabel,
				sp.Subject.Name,
				entry.Resource,
				entry.Actions,
				entry.RoleRef,
				entry.BindingRef,
			})
		}
	}
}

// subjectKindLabel returns the display label for a subject kind.
func subjectKindLabel(subj rbac.Subject) string {
	switch subj.Kind {
	case rbac.KindServiceAccount:
		return "Service Account"
	case rbac.KindUser:
		return "User"
	case rbac.KindGroup:
		return "Group"
	default:
		return string(subj.Kind)
	}
}

// printSubjectHeader writes the subject kind and name header line.
func printSubjectHeader(w io.Writer, subj rbac.Subject) {
	fmt.Fprintf(w, "\n%s: %s\n\n", subjectKindLabel(subj), subj.Name)
}

// formattedEntry is an intermediate representation for output.
type formattedEntry struct {
	Resource   string
	Actions    string
	RoleRef    string
	BindingRef string
}

// groupByResource consolidates permissions that share the same resource,
// merging actions and showing all role/binding sources.
func groupByResource(perms []rbac.Permission) []formattedEntry {
	// Use a map keyed by resource+role+binding to deduplicate
	type entryKey struct {
		Resource    string
		RoleType    string
		RoleName    string
		BindingType string
		BindingName string
		Namespace   string
	}

	seen := make(map[entryKey]*formattedEntry)
	var order []entryKey

	for _, p := range perms {
		key := entryKey{
			Resource:    p.Resource,
			RoleType:    p.RoleType,
			RoleName:    p.RoleName,
			BindingType: p.Source.BindingType,
			BindingName: p.Source.BindingName,
			Namespace:   p.Source.Namespace,
		}

		if existing, ok := seen[key]; ok {
			// Merge actions
			existing.Actions = mergeActions(existing.Actions, strings.Join(p.Actions, ","))
		} else {
			actions := strings.Join(p.Actions, ",")

			roleRef := fmt.Sprintf("%s: %s", strings.ToLower(p.RoleType), p.RoleName)

			var bindingRef string
			if p.Source.BindingType == "RoleBinding" {
				bindingRef = fmt.Sprintf("RoleBinding: %s: NS:<%s>", p.RoleName, p.Source.Namespace)
			} else {
				bindingRef = fmt.Sprintf("ClusterRoleBinding: %s", p.RoleName)
			}

			entry := &formattedEntry{
				Resource:   p.Resource,
				Actions:    actions,
				RoleRef:    roleRef,
				BindingRef: bindingRef,
			}
			seen[key] = entry
			order = append(order, key)
		}
	}

	var entries []formattedEntry
	for _, key := range order {
		entries = append(entries, *seen[key])
	}
	return entries
}

// mergeActions combines two comma-separated action lists, deduplicating.
func mergeActions(existing, new string) string {
	actionSet := make(map[string]struct{})
	var ordered []string

	for _, a := range strings.Split(existing, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			if _, ok := actionSet[a]; !ok {
				actionSet[a] = struct{}{}
				ordered = append(ordered, a)
			}
		}
	}
	for _, a := range strings.Split(new, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			if _, ok := actionSet[a]; !ok {
				actionSet[a] = struct{}{}
				ordered = append(ordered, a)
			}
		}
	}

	return strings.Join(ordered, ",")
}
