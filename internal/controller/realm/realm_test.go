/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package realm

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"
)

// Unlike many Kubernetes projects Crossplane does not use third party testing
// libraries, per the common Go test review comments. Crossplane encourages the
// use of table driven unit tests. The tests of the crossplane-runtime project
// are representative of the testing style Crossplane encourages.
//
// https://github.com/golang/go/wiki/TestComments
// https://github.com/crossplane/crossplane/blob/master/CONTRIBUTING.md#contributing-code

func TestObserve(t *testing.T) {
	type fields struct {
		service interface{} //nolint:all
	}

	type args struct {
		ctx context.Context
		mg  resource.Managed
	}

	type want struct {
		o   managed.ExternalObservation
		err error
	}

	cases := map[string]struct {
		reason string
		fields fields
		args   args
		want   want
	}{
		// TODO: Add test cases.
	}

	for name, testcase := range cases {
		t.Run(name, func(t *testing.T) {
			e := external{service: KeycloakService{}}
			got, err := e.Observe(testcase.args.ctx, testcase.args.mg)                     //nolint:all
			if diff := cmp.Diff(testcase.want.err, err, test.EquateErrors()); diff != "" { //nolint:all
				t.Errorf("\n%s\ne.Observe(...): -want error, +got error:\n%s\n", testcase.reason, diff) //nolint:all
			}
			if diff := cmp.Diff(testcase.want.o, got); diff != "" { //nolint:all
				t.Errorf("\n%s\ne.Observe(...): -want, +got:\n%s\n", testcase.reason, diff) //nolint:all
			}
		})
	}
}
